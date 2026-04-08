// SPDX-License-Identifier: GPL-2.0-only
/*
 * VMEXIT Dispatch Loop
 */

#include "ring_minus_one.h"
#include "svm_decode.h"
#include "svm_trace.h"
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/sched/signal.h>

/* State is now tracked per process in ctx->pending_rearm_gpa */

#define VMEXIT_MAX_ITERATIONS 100000

/* ═══════════════════════════════════════════════════════════════════════════
 *  Kill Switch — Matrix'in "Çıkışı"
 *
 *  Guest RAX + RBX magic pattern ile hypervisor'dan acil çıkış.
 *  Geliştirici güvenlik ağı: sonsuz döngü veya #PF ping-pong'da
 *  makineyi resetlemek yerine temiz çıkış sağlar.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define KILL_SWITCH_RAX 0xDEADBEEFDEADBEEFULL
#define KILL_SWITCH_RBX 0x1337133713371337ULL

/* Ping-Pong Guard: ardışık kernel #PF re-injection limiti */
#define KERNEL_PF_REINJECT_MAX 256
#define TSC_COMP_MAX_DELTA (30000000ULL)

/* ═══════════════════════════════════════════════════════════════════════════
 *  CPUID Handler — Anti-Detection Core
 *
 *  CPUID.1:ECX[31] = hypervisor present bit → cleared
 *  CPUID.0x40000000-0x4FFFFFFF = hypervisor leaves → zeroed
 *  All other leaves: native pass-through via host cpuid
 * ═══════════════════════════════════════════════════════════════════════════
 */

static void handle_cpuid(struct vmcb *vmcb, struct guest_regs *regs)
{
	u32 leaf = (u32)vmcb->save.rax;
	u32 subleaf = (u32)regs->rcx;
	u32 eax, ebx, ecx, edx;

	/* Güvenlik: Maksimum desteklenen leaf CPUID sorgusuna passthrough edilir,
	 * #GP enjeksiyonundan vazgeçildi
	 */

	/* Execute real CPUID on the host CPU */
	cpuid_count(leaf, subleaf, &eax, &ebx, &ecx, &edx);

	/* ── Stealth Filter: clear hypervisor present bit ── */
	if (leaf == 1)
		ecx &= ~(1U << 31);

	/* ── Stealth Filter: hide all hypervisor vendor leaves ── */
	if (leaf >= 0x40000000 && leaf <= 0x4FFFFFFF) {
		eax = 0;
		ebx = 0;
		ecx = 0;
		edx = 0;
	}

	/* Write results back to guest state */
	vmcb->save.rax = eax;
	regs->rbx = ebx;
	regs->rcx = ecx;
	regs->rdx = edx;

	/* Advance RIP using hardware-provided next_rip to avoid prefix injection
	 * crashes
	 */
	vmcb->save.rip = vmcb->control.next_rip;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  MSR Handler — Timing MSR Emulation
 *
 *  RDMSR: ECX = MSR number, result in EDX:EAX
 *  WRMSR: ECX = MSR number, value in EDX:EAX
 *  exit_info_1: bit 0 = 1 for WRMSR, 0 for RDMSR
 * ═══════════════════════════════════════════════════════════════════════════
 */

static void handle_msr(struct svm_context *ctx, struct guest_regs *regs)
{
	struct vmcb *vmcb = ctx->vmcb;
	u32 msr_num = (u32)regs->rcx;
	bool is_write = vmcb->control.exit_info_1 & 1;
	u64 val;

	if (is_write) {
		u64 wval = (regs->rdx << 32) | (vmcb->save.rax & 0xFFFFFFFFULL);

		switch (msr_num) {

		case 0xC0000100: /* MSR_FS_BASE */
		case 0xC0000101: /* MSR_GS_BASE */
		case 0xC0000102: /* MSR_KERNEL_GS_BASE */
			svm_trace_emit_log(LOG_EVENT_CR3_WRITE, vmcb->save.rip, wval,
					   vmcb->save.cr3);
			/* Native execute: TLS/SWAPGS bozulmamalı */
			wrmsrq(msr_num, wval);
			break;

		case 0x1D9: /* IA32_DEBUGCTL (Shadowing) */
			ctx->shadow_dbgctl = wval;
			/* Hardware'da LBR (bit 0) zorla açık kalır */
			vmcb->save.dbgctl = wval | 1ULL;
			break;

		default:
			/*
			 * Silently ignore writes to other intercepted MSRs.
			 * Writing to TSC/LSTAR/STAR could break host state.
			 */
			break;
		}

		vmcb->save.rip = vmcb->control.next_rip;
		return;
	}

	/* RDMSR: return real or compensated value */
	switch (msr_num) {
	case 0x10: /* IA32_TSC — return compensated TSC */
		val = rdtsc() + *this_cpu_ptr(&pcpu_tsc_offset);
		break;

	case 0xE7:  /* IA32_MPERF — pass through */
	case 0xE8:  /* IA32_APERF — pass through */
	case 0x176: /* IA32_SYSENTER_EIP — pass through */
		if (rdmsrq_safe(msr_num, &val))
			val = 0;
		break;

	case 0xC0000081: /* STAR */
	case 0xC0000082: /* LSTAR */
	case 0xC0000103: /* TSC_AUX */
		if (rdmsrq_safe(msr_num, &val))
			val = 0;
		break;

	case 0xC0010015: /* MSR_K8_HWCR — SVME_LOCK spoofing */
		if (rdmsrq_safe(msr_num, &val))
			val = 0;
		val |= (1ULL << 24); /* Force SVME_LOCK = 1 */
		break;

	case 0xC0010114: /* SVM_LOCK_KEY — hide SVM presence */
		/*
		 * If this MSR returns non-zero, programs know SVM is active.
		 * Return 0 to deny SVM presence evidence.
		 */
		val = 0;
		break;

	/* ── PMC MSRs: return frozen/zero counters ── */
	case 0x309: /* IA32_FIXED_CTR0 (instructions retired) */
	case 0x30A: /* IA32_FIXED_CTR1 (unhalted core cycles) */
	case 0x30B: /* IA32_FIXED_CTR2 (unhalted reference cycles) */

		if (rdmsrq_safe(msr_num, &val))
			val = 0;
		break;

	case 0x38D: /* IA32_PERF_FIXED_CTR_CTRL */
	case 0x38F: /* IA32_PERF_GLOBAL_CTRL */
		/* Pass through reads, block writes (handled in is_write above) */
		if (rdmsrq_safe(msr_num, &val))
			val = 0;
		break;

	/* ── Shadow DEBUGCTL ── */
	case 0x1D9: /* IA32_DEBUGCTL */
		val = ctx->shadow_dbgctl;
		break;

	default:
		/* Unknown MSR — return 0 to avoid #GP */
		val = 0;
		break;
	}

	vmcb->save.rax = val & 0xFFFFFFFFULL;
	regs->rdx = val >> 32;
	vmcb->save.rip = vmcb->control.next_rip;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  IOIO Handler — Timer Port Blocking
 *
 *  Blocks reads from PIT (0x40-0x43) and ACPI PM Timer (0x808-0x80B).
 *  Returns 0 for IN, ignores OUT. Uses NRIPS (next_rip) for safe advance.
 *
 *  exit_info_1 format (AMD APM Vol.2 §15.10.2):
 *    Bit 0:     TYPE  (0=OUT, 1=IN)
 *    Bits 4-6:  Size  (Bit4=byte, Bit5=word, Bit6=dword)
 *    Bits 16-31: Port number
 * ═══════════════════════════════════════════════════════════════════════════
 */

static void handle_ioio(struct vmcb *vmcb, struct guest_regs *regs)
{
	u64 info = vmcb->control.exit_info_1;
	bool is_in = info & SVM_IOIO_TYPE_MASK;

	(void)regs;

	if (is_in) {
		/* Return 0 for all blocked timer port reads */
		vmcb->save.rax = 0;
	}
	/* OUT: silently drop */

	/* Use NRIPS (hardware-provided next RIP) if available */
	if (vmcb->control.next_rip) {
		u64 next_rip = vmcb->control.next_rip;
		/* İşlemci zaten VMRUN ve branch işlemlerinde Non-canonical hesaplamasını
		 * yapıp #GP üretecektir, bu manuel kontrol gereksiz bir redundancydir ve hardware
		 * layerina devredildi.
		 */
		vmcb->save.rip = next_rip;
	} else {
		vmcb->save.rip += 1; /* Conservative: IN al,dx = 1 byte (EC) */
	}
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  RDTSCP Handler
 *
 *  Returns compensated TSC in EDX:EAX + TSC_AUX in ECX.
 *  RDTSCP = 0F 01 F9 = 3 bytes
 * ═══════════════════════════════════════════════════════════════════════════
 */

static void handle_rdtscp(struct vmcb *vmcb, struct guest_regs *regs)
{
	u64 tsc = rdtsc() + *this_cpu_ptr(&pcpu_tsc_offset);
	u64 tsc_aux;

	vmcb->save.rax = tsc & 0xFFFFFFFFULL;
	regs->rdx = tsc >> 32;

	/* Read real TSC_AUX for core ID */
	if (rdmsrq_safe(0xC0000103, &tsc_aux))
		tsc_aux = 0;
	regs->rcx = tsc_aux & 0xFFFFFFFFULL;

	vmcb->save.rip = vmcb->control.next_rip;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Main Dispatch Loop — TSC-Compensated VMRUN with VMEXIT Handling
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* DEFINE_PER_CPU states for context tracking */
static DEFINE_PER_CPU(u64, last_exit_tsc);
static DEFINE_PER_CPU(u64, last_guest_rip);

int svm_run_guest(struct svm_context *ctx, struct guest_regs *regs)
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

	if (!regs)
		return -ENOMEM;

	/* Log removed for fastpath */

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

	host_fs_base = native_read_msr(MSR_FS_BASE);
	host_gs_base = native_read_msr(MSR_GS_BASE);
	host_kernel_gs_base = native_read_msr(MSR_KERNEL_GS_BASE);
	host_star = native_read_msr(MSR_STAR);
	host_lstar = native_read_msr(MSR_LSTAR);
	host_cstar = native_read_msr(MSR_CSTAR);
	host_sfmask = native_read_msr(MSR_SYSCALL_MASK);
	host_sysenter_cs = native_read_msr(MSR_IA32_SYSENTER_CS);
	host_sysenter_esp = native_read_msr(MSR_IA32_SYSENTER_ESP);
	host_sysenter_eip = native_read_msr(MSR_IA32_SYSENTER_EIP);

	/* Phase 26: Pass VMCB Virtual Address as 3rd parameter for Assembly zero-stack decoding */
	vmrun_with_regs(ctx->vmcb_pa, regs, ctx->vmcb);

	asm volatile("lldt %0" ::"rm"(host_ldt_sel));

	native_write_msr(MSR_FS_BASE, host_fs_base);
	native_write_msr(MSR_GS_BASE, host_gs_base);
	native_write_msr(MSR_KERNEL_GS_BASE, host_kernel_gs_base);
	native_write_msr(MSR_STAR, host_star);
	native_write_msr(MSR_LSTAR, host_lstar);
	native_write_msr(MSR_CSTAR, host_cstar);
	native_write_msr(MSR_SYSCALL_MASK, host_sfmask);
	native_write_msr(MSR_IA32_SYSENTER_CS, host_sysenter_cs);
	native_write_msr(MSR_IA32_SYSENTER_ESP, host_sysenter_esp);
	native_write_msr(MSR_IA32_SYSENTER_EIP, host_sysenter_eip);

	host_start = rdtsc();

	local_irq_restore(flags);
	preempt_enable();

	exit_code = ((u64)ctx->vmcb->control.exit_code_hi << 32) | ctx->vmcb->control.exit_code;

	u64 current_rip = ctx->vmcb->save.rip;
	u64 *p_last_tsc = this_cpu_ptr(&last_exit_tsc);
	u64 *p_last_rip = this_cpu_ptr(&last_guest_rip);

	u64 now = rdtsc();
	u64 tsc_since_last_exit = now - *p_last_tsc;
	u64 rip_diff = current_rip - *p_last_rip;

	if (current_rip < *p_last_rip)
		rip_diff = *p_last_rip - current_rip;

	/* ── Load-Dependent Jitter ── */
	u64 load_factor = (tsc_since_last_exit < 15000) ? 5 : 30;
	u64 jitter = tsc_jitter(0, load_factor) + (load_factor / 2);

	/* ── Target Cost Heuristics (Predictive Scheduler) ── */
	s64 target_cost = 90; // Default fast CPUID

	if (likely(exit_code == SVM_EXIT_NPF)) {
		/* Fast-Path for #NPF (No cost modifiers needed) */
	} else if (likely(exit_code == SVM_EXIT_CPUID)) {
		u32 leaf = (u32)ctx->vmcb->save.rax;
		if (leaf >= 0x0B)
			target_cost = -100;
		else if (tsc_since_last_exit < 15000 && rip_diff < 32) {
			target_cost = 30;
			jitter = 0;
		} else {
			target_cost = 80;
		}
	} else if (exit_code == SVM_EXIT_MSR) {
		target_cost = 120;
	} else if (exit_code == SVM_EXIT_IOIO) {
		target_cost = 250;
	}

	/* ── Branch Prediction Optimized Dispatch ── */
	if (likely(exit_code == SVM_EXIT_NPF)) {
		u64 gpa = ctx->vmcb->control.exit_info_2;
		u64 npf_entry_tsc = rdtsc(); /* TSC Compensation */

		/* NPF Infinite Loop Guard */
		if (unlikely(gpa == ctx->last_npf_gpa)) {
			ctx->npf_loop_count++;
			if (unlikely(ctx->npf_loop_count > 10000)) {
				svm_trace_emit_log(LOG_EVENT_NPF_FATAL, ctx->vmcb->save.rip, gpa,
						   0xDEAD);
				ctx->npf_loop_count = 0;
				ret = 1;
				goto out;
			}
		} else {
			ctx->last_npf_gpa = gpa;
			ctx->npf_loop_count = 0;
		}

		handle_npf(ctx, npf_entry_tsc);
		goto post_dispatch;
	} else if (likely(exit_code == SVM_EXIT_CPUID)) {
		handle_cpuid(ctx->vmcb, regs);
		goto post_dispatch;
	}

	/* ── Cold Path (Slow Exits) ── */
	switch (exit_code) {
	case SVM_EXIT_HLT:
		svm_trace_emit_log(LOG_EVENT_GUEST_HLT, ctx->vmcb->save.rip, 0, 0);
		ret = 1; /* signal to break outer loop in ioctl */
		goto out;

	case SVM_EXIT_MSR:
		handle_msr(ctx, regs);
		break;

	case SVM_EXIT_IOIO:
		handle_ioio(ctx->vmcb, regs);
		break;

#ifdef SVM_EXIT_RDTSCP
	case SVM_EXIT_RDTSCP:
		handle_rdtscp(ctx->vmcb, regs);
		break;
#endif

	case SVM_EXIT_EXCP_BASE + 6: { /* #UD (Invalid Opcode) */
		u8 opcode[2] = {0};

		/*
		 * Userspace Micro-Hypervisor Syscall Proxy (Trampoline Passthrough)
		 * EFER.SCE=0 generates #UD for SYSCALL (0x0F 0x05).
		 */
		if (copy_from_user(opcode, (void __user *)ctx->vmcb->save.rip, 2) == 0) {
			if (opcode[0] == 0x0F && opcode[1] == 0x05) {
				/*
				 * Raw SYSCALL Instruction Trap!
				 * We do NOT emulate here. We advance RIP by 2 bytes exactly,
				 * and return '2' to orchestrate a Userspace Trampoline Proxy pass.
				 *
				 * CRITICAL ABI REQUIREMENT:
				 * Natively, the 'syscall' hardware instruction clobbers RCX (saves
				 * return RIP) and R11 (saves RFLAGS). Because we trap it via #UD
				 * *before* hardware execution, we MUST emulate this clobbering
				 * manually, or glibc will silently crash!
				 */
				u64 syscall_nr = ctx->vmcb->save.rax;

				if (syscall_nr == 60 || syscall_nr == 231) {
					svm_trace_emit_log(LOG_EVENT_PROXY_HLT, ctx->vmcb->save.rip,
							   syscall_nr, 0);
					ret = 1; /* Structural termination of the VMRUN, clears
						  * locks gracefully.
						  */
					break;
				}

				regs->rcx = ctx->vmcb->save.rip + 2;
				regs->r11 = ctx->vmcb->save.rflags;

				ctx->vmcb->save.rip += 2;
				ret = 2; /* Passthrough to Host Trampoline */
				break; /* Flow down to Trace / LBR Emission, then gracefully jump to
					* Userspace!
					*/
			}
		}

		svm_trace_emit_log(LOG_EVENT_UD_FAULT, ctx->vmcb->save.rip, 0, 0);
		return -EINVAL; /* Fatal exception, terminate hypervisor */
	}

	case SVM_EXIT_EXCP_BASE + 14: { /* #PF (Page Fault) */
		u64 fault_va = ctx->vmcb->control.exit_info_2;
		u64 error_code = ctx->vmcb->control.exit_info_1;
		u8 dummy;

		/*
		 * Kill Switch: Guest magic register pattern ile acil çıkış.
		 * RAX=0xDEADBEEF... + RBX=0x1337... → temiz Matrix eject.
		 */
		if (unlikely(ctx->vmcb->save.rax == KILL_SWITCH_RAX &&
			     regs->rbx == KILL_SWITCH_RBX)) {
			svm_trace_emit_log(LOG_EVENT_NPF_FATAL, ctx->vmcb->save.rip, fault_va,
					   0xDEAD);
			ctx->kernel_pf_count = 0;
			ret = 1;
			break;
		}

		/*
		 * Kernel-space #PF: Guest kernel'in kendi #PF handler'ına
		 * geri enjekte et. SYSCALL path'inde demand paging, per-CPU
		 * erişimi vb. meşru sayfa hatalarıdır.
		 * AMD APM Vol.2 §15.20: Event Injection
		 */
		if (unlikely(fault_va >= TASK_SIZE_MAX)) {
			/* Ping-Pong Guard: ardışık re-injection sayacı */
			ctx->kernel_pf_count++;
			if (unlikely(ctx->kernel_pf_count > KERNEL_PF_REINJECT_MAX)) {
				svm_trace_emit_log(LOG_EVENT_PONG_GUARD, ctx->vmcb->save.rip,
						   ctx->kernel_pf_count, 0);
				ctx->kernel_pf_count = 0;
				ret = 1;
				break;
			}

			ctx->vmcb->control.event_inj =
			    SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT | SVM_EVTINJ_VALID_ERR | 14;
			ctx->vmcb->control.event_inj_err = error_code;
			ctx->vmcb->save.cr2 = fault_va;
			ret = 0;
			break;
		}

		/* User-space #PF — sayacı sıfırla */
		ctx->kernel_pf_count = 0;

		/*
		 * Ghost Target Demand Paging / CoW Proxy
		 * Linux uses lazy demand paging. The first time a process touches its own
		 * mapped ELF or Library pages, it triggers a #PF. If we eject here, we
		 * lose the Matrix. We can force the Host Kernel to fault-in the page
		 * safely by simulating a read (or write) to the faulting user virtual
		 * address.
		 */
		if (copy_from_user(&dummy, (void __user *)fault_va, 1) == 0) {
			if (error_code & 2) { /* The #PF was caused by a Write Access, force CoW */
				if (copy_to_user((void __user *)fault_va, &dummy, 1)) {
					svm_trace_emit_log(LOG_EVENT_NPF_FATAL, ctx->vmcb->save.rip,
							   fault_va, 0);
					ret = 1;
					break;
				}
			}
			/* Page is now physically backed by Host Kernel. Re-enter VMRUN! */
			ret = 0;
			break;
		}

		/* Real Segmentation Fault / Invalid Memory Access */
		svm_trace_emit_log(LOG_EVENT_NPF_FATAL, ctx->vmcb->save.rip, fault_va, error_code);
		ret = 1;
		break; /* Graceful exit with Telemetry */
	}

	case 0x60: /* SVM_EXIT_INTR */
	case 0x61: /* SVM_EXIT_NMI */
		/* Host physical interrupt (e.g. Timer tick or Watchdog). Safe exit and loop
		 * back!
		 */
		ret = 0;
		break;

	case SVM_EXIT_EXCP_BASE + 1: { /* #DB */
		u64 *p_rearm = &ctx->pending_rearm_gpa;

		ctx->vmcb->save.rflags &= ~RFLAGS_TF;
		ctx->vmcb->control.intercepts[INTERCEPT_EXCEPTION_OFFSET >> 5] &= ~EXCEPT_DB_BIT;

		if (*p_rearm) {
			u64 g = *p_rearm;

			if (pfn_valid(g >> PAGE_SHIFT)) {
				u64 *pml4 = ctx->npt.pml4;
				int pml4i = (g >> 39) & 0x1FF;
				int pdpti = (g >> 30) & 0x1FF;
				int pdi = (g >> 21) & 0x1FF;

				u64 pdpt_phys = pml4[pml4i] & 0x000FFFFFFFFFF000ULL;

				if (pdpt_phys && pfn_valid(pdpt_phys >> PAGE_SHIFT)) {
					u64 *pdpt = (u64 *)phys_to_virt(pdpt_phys);
					u64 pd_phys = pdpt[pdpti] & 0x000FFFFFFFFFF000ULL;

					if (pd_phys && pfn_valid(pd_phys >> PAGE_SHIFT)) {
						u64 *pd = (u64 *)phys_to_virt(pd_phys);

						/* Phase 21: Correctly re-arm NX or Write based on
						 * fault type */
						if (ctx->pending_rearm_nx) {
							pd[pdi] |= NPT_NX; /* Execute korumasını
									      geri koy */
							ctx->pending_rearm_nx = 0;
						} else {
							pd[pdi] &= ~NPT_WRITE; /* Write korumasını
										  geri koy */
						}
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
		svm_trace_emit_log(LOG_EVENT_UNHANDLED_EXIT, ctx->vmcb->save.rip, exit_code, 0);
		ret = -EIO;
		goto out;

	default:
		svm_trace_emit_log(LOG_EVENT_UNHANDLED_EXIT, ctx->vmcb->save.rip, exit_code, 0);
		ret = -EIO;
		goto out;
	}

post_dispatch:
	/* ── Phase 2: LBR Chronological Drain ── */
	{
		u8 lbr_insn[32] = {0};
		u32 lbr_insn_len = 0;
		u64 lbr_hpa = npt_get_hpa(&ctx->npt, ctx->vmcb->save.rip);

		if (lbr_hpa && pfn_valid(lbr_hpa >> PAGE_SHIFT)) {
			void *lbr_hva = phys_to_virt(lbr_hpa);
			size_t avail = PAGE_SIZE - (lbr_hpa & ~PAGE_MASK);

			if (avail > sizeof(lbr_insn))
				avail = sizeof(lbr_insn);
			if (!copy_from_kernel_nofault(lbr_insn, lbr_hva, avail))
				lbr_insn_len = (u32)avail;
		}

		svm_trace_emit_lbr(ctx->vmcb->save.cr3, ctx->vmcb->save.rip,
				   ctx->vmcb->save.br_from, ctx->vmcb->save.br_to, lbr_insn,
				   lbr_insn_len);
	}

	/* ── TSC Compensation (runs with IRQs ENABLED — safe, pinned to CPU 0) ── */
	{
		u64 host_end = rdtsc();
		u64 host_processing = host_end - host_start;
		u64 hw_overhead = 1000;

		s64 refund = (s64)(host_processing + hw_overhead) - (target_cost + jitter);

		if (refund > 500000LL)
			refund = 500000LL;
		if (refund < -500000LL)
			refund = -500000LL;

		*offset -= refund;

		if (*offset > 10000000000LL)
			*offset = 10000000000LL;
		if (*offset < -10000000000LL)
			*offset = -10000000000LL;

		ctx->vmcb->control.tsc_offset = *offset;

		// Gerçekliğe uyan!

		ctx->vmcb->control.clean |= VMCB_CLEAN_ALL;
		ctx->vmcb->control.clean &= ~VMCB_CLEAN_TSC;

		*p_last_tsc = rdtsc();
		*p_last_rip = current_rip;
	}

out:
	return ret;
}
