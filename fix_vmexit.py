with open('/home/hakan/kernel/vmexit.c', 'r') as f:
    content = f.read()

import re
import sys

new_func = """int svm_run_guest(struct svm_context *ctx, struct guest_regs *regs)
{
    u64 exit_code;
    int ret = 0;
    unsigned long flags;
    s64 *offset;
    u64 host_start;

    /* Dynamic Host Context Preservation */
    u64 host_kernel_gs_base, host_star, host_lstar;
    u64 host_cstar, host_sfmask;
    u64 host_sysenter_cs, host_sysenter_esp, host_sysenter_eip;
    u64 host_fs_base, host_gs_base;
    u16 host_fs_sel, host_gs_sel, host_ldt_sel;

    if (!regs) return -ENOMEM;

    pr_info_once("[VMEXIT] First userspace thread entered Matrix.\\n");

    /* İlk VMRUN */
    offset = this_cpu_ptr(&pcpu_tsc_offset);
    ctx->vmcb->control.tsc_offset = *offset;
    ctx->vmcb->control.clean = 0;

    preempt_disable();
    local_irq_save(flags);

    /* ── SAVE DYNAMIC HOST CONTEXT BEFORE VMRUN ── */
    asm volatile("mov %%fs, %0" : "=rm"(host_fs_sel));
    asm volatile("mov %%gs, %0" : "=rm"(host_gs_sel));
    asm volatile("sldt %0" : "=rm"(host_ldt_sel));
    
    host_fs_base        = native_read_msr(MSR_FS_BASE);
    host_gs_base        = native_read_msr(MSR_GS_BASE);
    host_kernel_gs_base = native_read_msr(MSR_KERNEL_GS_BASE);
    host_star           = native_read_msr(MSR_STAR);
    host_lstar          = native_read_msr(MSR_LSTAR);
    host_cstar          = native_read_msr(MSR_CSTAR);
    host_sfmask         = native_read_msr(MSR_SYSCALL_MASK);
    host_sysenter_cs    = native_read_msr(MSR_IA32_SYSENTER_CS);
    host_sysenter_esp   = native_read_msr(MSR_IA32_SYSENTER_ESP);
    host_sysenter_eip   = native_read_msr(MSR_IA32_SYSENTER_EIP);

    vmrun_with_regs(ctx->vmcb_pa, regs);

    /*
     * CRITICAL: Do NOT reload FS/GS selectors!
     * 'mov %%gs' zeroes GS_BASE. Write MSRs directly.
     */
    asm volatile("lldt %0" :: "rm"(host_ldt_sel));

    native_write_msr(MSR_FS_BASE,          host_fs_base);
    native_write_msr(MSR_GS_BASE,          host_gs_base);
    native_write_msr(MSR_KERNEL_GS_BASE,   host_kernel_gs_base);
    native_write_msr(MSR_STAR,             host_star);
    native_write_msr(MSR_LSTAR,            host_lstar);
    native_write_msr(MSR_CSTAR,            host_cstar);
    native_write_msr(MSR_SYSCALL_MASK,     host_sfmask);
    native_write_msr(MSR_IA32_SYSENTER_CS, host_sysenter_cs);
    native_write_msr(MSR_IA32_SYSENTER_ESP,host_sysenter_esp);
    native_write_msr(MSR_IA32_SYSENTER_EIP,host_sysenter_eip);

    host_start = rdtsc();

    local_irq_restore(flags);
    preempt_enable();

    exit_code = ((u64)ctx->vmcb->control.exit_code_hi << 32) |
                 ctx->vmcb->control.exit_code;
                 
    u64 current_rip = ctx->vmcb->save.rip;
    u64 *p_last_tsc = this_cpu_ptr(&last_exit_tsc);
    u64 *p_last_rip = this_cpu_ptr(&last_guest_rip);
    
    u64 now = rdtsc();
    u64 tsc_since_last_exit = now - *p_last_tsc;
    u64 rip_diff = current_rip - *p_last_rip;
    if (current_rip < *p_last_rip) rip_diff = *p_last_rip - current_rip;

    /* ── Load-Dependent Jitter ── */
    u64 load_factor = (tsc_since_last_exit < 15000) ? 5 : 30;
    u64 jitter = tsc_jitter(0, load_factor) + (load_factor / 2);

    /* ── Target Cost Heuristics (Predictive Scheduler) ── */
    s64 target_cost = 90; // Default fast CPUID
    
    switch (exit_code) {
    case SVM_EXIT_CPUID: {
        u32 leaf = (u32)ctx->vmcb->save.rax;
        if (leaf >= 0x0B) target_cost = -100;
        else if (tsc_since_last_exit < 15000 && rip_diff < 32) {
            target_cost = 30;
            jitter = 0;
        } else {
            target_cost = 80;
        }
        break;
    }
    case SVM_EXIT_MSR:   target_cost = 120; break;
    case SVM_EXIT_IOIO:  target_cost = 250; break;
    }

    /* ── Dispatch (Host İşlemleri) ── */
    switch (exit_code) {
    case SVM_EXIT_CPUID:
        handle_cpuid(ctx->vmcb, regs);
        break;

    case SVM_EXIT_HLT:
        pr_info("[VMEXIT] Guest HLT — normal exit (0x78)\\n");
        ret = 1; /* signal to break outer loop in ioctl */
        goto out;

    case SVM_EXIT_MSR:
        handle_msr(ctx->vmcb, regs);
        break;

    case SVM_EXIT_IOIO:
        handle_ioio(ctx->vmcb, regs);
        break;

#ifdef SVM_EXIT_RDTSCP
    case SVM_EXIT_RDTSCP:
        handle_rdtscp(ctx->vmcb, regs);
        break;
#endif

    case SVM_EXIT_NPF: {
        u64 info1 = ctx->vmcb->control.exit_info_1;
        u64 gpa   = ctx->vmcb->control.exit_info_2;

        if (info1 & NPF_INFO1_WRITE) {
            if (!pfn_valid(gpa >> PAGE_SHIFT)) break;
                
            void *hva = phys_to_virt(gpa & PAGE_MASK);
            svm_trace_emit_dirty(
                ctx->vmcb->save.cr3,
                ctx->vmcb->save.rip,
                gpa & PAGE_MASK,
                hva);

            {
                u64 *pml4 = ctx->npt.pml4;
                int pml4i = (gpa >> 39) & 0x1FF;
                int pdpti = (gpa >> 30) & 0x1FF;
                int pdi   = (gpa >> 21) & 0x1FF;
                
                u64 pdpt_phys = pml4[pml4i] & ~0xFFFULL;
                if (!pdpt_phys || !pfn_valid(pdpt_phys >> PAGE_SHIFT)) goto skip_rearm;
                u64 *pdpt = phys_to_virt(pdpt_phys);
                
                u64 pd_phys = pdpt[pdpti] & ~0xFFFULL;
                if (!pd_phys || !pfn_valid(pd_phys >> PAGE_SHIFT)) goto skip_rearm;
                u64 *pd   = phys_to_virt(pd_phys);
                
                pd[pdi]  |= NPT_WRITE;
            }

skip_rearm:
            ctx->vmcb->save.rflags |= RFLAGS_TF;
            ctx->vmcb->control.intercepts[INTERCEPT_EXCEPTION >> 5] |= EXCEPT_DB_BIT;
            *this_cpu_ptr(&pending_rearm_gpa) = gpa & PAGE_MASK;
            ctx->vmcb->control.clean &= ~(VMCB_CLEAN_NP | VMCB_CLEAN_INTERCEPTS);
        }
        break;
    }

    case SVM_EXIT_EXCP_BASE + 1: {  /* #DB */
        u64 *p_rearm = this_cpu_ptr(&pending_rearm_gpa);
        
        ctx->vmcb->save.rflags &= ~RFLAGS_TF;
        ctx->vmcb->control.intercepts[INTERCEPT_EXCEPTION >> 5] &= ~EXCEPT_DB_BIT;

        if (*p_rearm) {
            u64 g = *p_rearm;
            if (pfn_valid(g >> PAGE_SHIFT)) {
                u64 *pml4 = ctx->npt.pml4;
                int pml4i = (g >> 39) & 0x1FF;
                int pdpti = (g >> 30) & 0x1FF;
                int pdi   = (g >> 21) & 0x1FF;
                
                u64 pdpt_phys = pml4[pml4i] & ~0xFFFULL;
                if (pdpt_phys && pfn_valid(pdpt_phys >> PAGE_SHIFT)) {
                    u64 *pdpt = phys_to_virt(pdpt_phys);
                    u64 pd_phys = pdpt[pdpti] & ~0xFFFULL;
                    if (pd_phys && pfn_valid(pd_phys >> PAGE_SHIFT)) {
                        u64 *pd = phys_to_virt(pd_phys);
                        pd[pdi] &= ~NPT_WRITE;
                    }
                }
            }
            *p_rearm = 0;
            raw_cr3_flush();
        }
        ctx->vmcb->control.clean &= ~(VMCB_CLEAN_NP | VMCB_CLEAN_INTERCEPTS);
        break;
    }

    case 0xFFFFFFFFFFFFFFFFULL:
        pr_err("[VMEXIT] VMEXIT_INVALID — VMCB misconfigured!\\n");
        ret = -EIO;
        goto out;

    default:
        pr_warn("[VMEXIT] Unhandled exit: 0x%llx at RIP=0x%llx\\n",
                exit_code, ctx->vmcb->save.rip);
        ret = -EIO;
        goto out;
    }

    /* ── Phase 2: LBR Chronological Drain ── */
    svm_trace_emit_lbr(ctx->vmcb->save.cr3, ctx->vmcb->save.rip);

    /* ── TSC Compensation (runs with IRQs ENABLED — safe, pinned to CPU 0) ── */
    {
        u64 host_end = rdtsc();
        u64 host_processing = host_end - host_start;
        u64 hw_overhead = 1000;

        s64 refund = (s64)(host_processing + hw_overhead) - (target_cost + jitter);
        
        if (refund > 500000LL) refund = 500000LL;
        if (refund < -500000LL) refund = -500000LL;

        *offset -= refund;

        if (*offset > 10000000000LL) *offset = 10000000000LL;
        if (*offset < -10000000000LL) *offset = -10000000000LL;

        ctx->vmcb->control.tsc_offset = *offset;
        ctx->vmcb->control.clean = VMCB_CLEAN_STABLE;
        
        *p_last_tsc = rdtsc();
        *p_last_rip = current_rip;
    }

out:
    return ret;
}
"""

pattern = r"int svm_run_guest\(struct svm_context \*ctx\)\n\{.*"
new_content = re.sub(pattern, new_func, content, flags=re.DOTALL)

with open('/home/hakan/kernel/vmexit.c', 'w') as f:
    f.write(new_content)
