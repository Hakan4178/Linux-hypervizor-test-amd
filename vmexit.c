/*
 * vmexit.c — VMEXIT Dispatch Loop (V4.1 Stealth)
 *
 * Full VMEXIT handler with:
 *  - CPUID stealth (hypervisor bit cleared, vendor leaves hidden)
 *  - MSR emulation (TSC compensation, pass-through)
 *  - I/O port blocking (PIT, ACPI PM Timer)
 *  - Per-CPU TSC compensation integrated into the loop
 *  - VMCB clean bits for minimal timing jitter
 */

#include "ring_minus_one.h"

#define VMEXIT_MAX_ITERATIONS 100000

/* ═══════════════════════════════════════════════════════════════════════════
 *  TSC Jitter PRNG — Anti Timing Analysis
 *
 *  Without jitter: every CPUID takes exactly N cycles → detected as emulated.
 *  With jitter: Gaussian-like noise makes timing look like real hardware
 *  (cache miss, pipeline stall, branch misprediction variance).
 *
 *  Uses a fast 64-bit LCG (Linear Congruential Generator).
 * ═══════════════════════════════════════════════════════════════════════════ */

static u64 jitter_state = 0x5DEECE66DULL;

static inline u64 tsc_jitter(u64 min, u64 max)
{
    /* LCG: state = state * 6364136223846793005 + 1442695040888963407 */
    jitter_state = jitter_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return min + ((jitter_state >> 33) % (max - min + 1));
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CPUID Handler — Anti-Detection Core
 *
 *  CPUID.1:ECX[31] = hypervisor present bit → cleared
 *  CPUID.0x40000000-0x4FFFFFFF = hypervisor leaves → zeroed
 *  All other leaves: native pass-through via host cpuid
 * ═══════════════════════════════════════════════════════════════════════════ */

static void handle_cpuid(struct vmcb *vmcb, struct guest_regs *regs)
{
    u32 leaf    = (u32)vmcb->save.rax;
    u32 subleaf = (u32)regs->rcx;
    u32 eax, ebx, ecx, edx;

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

    /* Advance RIP past CPUID instruction (0F A2 = 2 bytes) */
    vmcb->save.rip += 2;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  MSR Handler — Timing MSR Emulation
 *
 *  RDMSR: ECX = MSR number, result in EDX:EAX
 *  WRMSR: ECX = MSR number, value in EDX:EAX
 *  exit_info_1: bit 0 = 1 for WRMSR, 0 for RDMSR
 * ═══════════════════════════════════════════════════════════════════════════ */

static void handle_msr(struct vmcb *vmcb, struct guest_regs *regs)
{
    u32 msr_num  = (u32)regs->rcx;
    bool is_write = vmcb->control.exit_info_1 & 1;
    u64 val;

    if (is_write) {
        /*
         * Silently ignore writes to intercepted MSRs.
         * Writing to TSC/LSTAR/STAR could break host state.
         */
        vmcb->save.rip += 2;  /* WRMSR = 0F 30 */
        return;
    }

    /* RDMSR: return real or compensated value */
    switch (msr_num) {
    case 0x10:  /* IA32_TSC — return compensated TSC */
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
        val |= (1ULL << 24);  /* Force SVME_LOCK = 1 */
        break;

    case 0xC0010114: /* SVM_LOCK_KEY — hide SVM presence */
        /*
         * If this MSR returns non-zero, programs know SVM is active.
         * Return 0 to deny SVM presence evidence.
         */
        val = 0;
        break;

    /* ── PMC MSRs: return frozen/zero counters ── */
    case 0x309:  /* IA32_FIXED_CTR0 (instructions retired) */
    case 0x30A:  /* IA32_FIXED_CTR1 (unhalted core cycles) */
    case 0x30B:  /* IA32_FIXED_CTR2 (unhalted reference cycles) */
        /*
         * EAC reads these to detect extra micro-ops from VMEXIT.
         * Return real value — the overhead is hidden by TSC compensation.
         * These counters are hardware and can't be easily faked,
         * but intercepting prevents cross-correlation attacks.
         */
        if (rdmsrq_safe(msr_num, &val))
            val = 0;
        break;

    case 0x38D:  /* IA32_PERF_FIXED_CTR_CTRL */
    case 0x38F:  /* IA32_PERF_GLOBAL_CTRL */
        /* Pass through reads, block writes (handled in is_write above) */
        if (rdmsrq_safe(msr_num, &val))
            val = 0;
        break;

    /* ── BTS: Block Branch Trace Store ── */
    case 0x1D9:  /* IA32_DEBUGCTL */
        /*
         * BTS (Branch Trace Store) can record VMRUN branch target.
         * We intercept reads to return value with BTS bits cleared,
         * and intercept writes to silently ignore BTS enable.
         */
        if (rdmsrq_safe(msr_num, &val))
            val = 0;
        val &= ~(3ULL);      /* Clear bits 0-1 (LBR, BTF) */
        val &= ~(1ULL << 6); /* Clear bit 6 (TR — trace messages) */
        val &= ~(1ULL << 7); /* Clear bit 7 (BTS — branch trace store) */
        val &= ~(1ULL << 9); /* Clear bit 9 (BTS_OFF_OS) */
        break;

    default:
        /* Unknown MSR — return 0 to avoid #GP */
        val = 0;
        break;
    }

    vmcb->save.rax = val & 0xFFFFFFFFULL;
    regs->rdx      = val >> 32;
    vmcb->save.rip += 2;  /* RDMSR = 0F 32 */
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
 * ═══════════════════════════════════════════════════════════════════════════ */

static void handle_ioio(struct vmcb *vmcb, struct guest_regs *regs)
{
    u64 info       = vmcb->control.exit_info_1;
    bool is_in     = info & SVM_IOIO_TYPE_MASK;

    (void)regs;

    if (is_in) {
        /* Return 0 for all blocked timer port reads */
        vmcb->save.rax = 0;
    }
    /* OUT: silently drop */

    /* Use NRIPS (hardware-provided next RIP) if available */
    if (vmcb->control.next_rip)
        vmcb->save.rip = vmcb->control.next_rip;
    else
        vmcb->save.rip += 1;  /* Conservative: IN al,dx = 1 byte (EC) */
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  RDTSCP Handler
 *
 *  Returns compensated TSC in EDX:EAX + TSC_AUX in ECX.
 *  RDTSCP = 0F 01 F9 = 3 bytes
 * ═══════════════════════════════════════════════════════════════════════════ */

static void handle_rdtscp(struct vmcb *vmcb, struct guest_regs *regs)
{
    u64 tsc = rdtsc() + *this_cpu_ptr(&pcpu_tsc_offset);
    u64 tsc_aux;

    vmcb->save.rax = tsc & 0xFFFFFFFFULL;
    regs->rdx      = tsc >> 32;

    /* Read real TSC_AUX for core ID */
    if (rdmsrq_safe(0xC0000103, &tsc_aux))
        tsc_aux = 0;
    regs->rcx = tsc_aux & 0xFFFFFFFFULL;

    vmcb->save.rip += 3;  /* RDTSCP = 0F 01 F9 */
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Main Dispatch Loop — TSC-Compensated VMRUN with VMEXIT Handling
 * ═══════════════════════════════════════════════════════════════════════════ */

/* DEFINE_PER_CPU states for context tracking */
static DEFINE_PER_CPU(u64, last_exit_tsc);
static DEFINE_PER_CPU(u64, last_guest_rip);

int svm_run_guest(struct svm_context *ctx)
{
    struct guest_regs regs = {0};
    u64 exit_code;
    int iter = VMEXIT_MAX_ITERATIONS;
    int ret = 0;
    unsigned long flags;
    s64 *offset;
    u64 host_start;

    pr_info("[VMEXIT] Entering guest dispatch loop (Predictive Context)\n");

    /* İlk VMRUN */
    offset = this_cpu_ptr(&pcpu_tsc_offset);
    ctx->vmcb->control.tsc_offset = *offset;
    ctx->vmcb->control.clean = 0;

    preempt_disable();
    local_irq_save(flags);

    vmrun_with_regs(ctx->vmcb_pa, &regs);
    host_start = rdtsc();

    local_irq_restore(flags);
    preempt_enable();

    while (iter-- > 0) {
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
            
            /* 1. Topology / Extended Leaf Pre-emptive Lag Absorption 
             * MUST BE FIRST! If cache heater overrides this, physical hw lag exposes LeafB! */
            if (leaf >= 0x0B) {
                target_cost = -100;
            }
            /* 2. Cache Heater (Back-to-Back CPUID & Sandwich Pipeline) */
            else if (tsc_since_last_exit < 15000 && rip_diff < 32) {
                target_cost = 30;  // Extremely fast, reflects L1 hit
                jitter = 0;        // Absolute stability
            }
            /* 3. Standard Fast CPUID (vs FYL2XP1) */
            else {
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
            handle_cpuid(ctx->vmcb, &regs);
            break;

        case SVM_EXIT_HLT:
            pr_info("[VMEXIT] Guest HLT — normal exit (0x78)\n");
            ret = 0;
            goto out;

        case SVM_EXIT_MSR:
            handle_msr(ctx->vmcb, &regs);
            break;

        case SVM_EXIT_IOIO:
            handle_ioio(ctx->vmcb, &regs);
            break;

#ifdef SVM_EXIT_RDTSCP
        case SVM_EXIT_RDTSCP:
            handle_rdtscp(ctx->vmcb, &regs);
            break;
#endif

        case 0xFFFFFFFFFFFFFFFFULL:
            pr_err("[VMEXIT] VMEXIT_INVALID — VMCB misconfigured!\n");
            ret = -EIO;
            goto out;

        default:
            pr_warn("[VMEXIT] Unhandled exit: 0x%llx at RIP=0x%llx\n",
                    exit_code, ctx->vmcb->save.rip);
            ret = -EIO;
            goto out;
        }

        /* ── Ayrıştırılmış TSC Telafisi ── */
        preempt_disable();
        local_irq_save(flags);

        u64 host_end = rdtsc();
        u64 host_processing = host_end - host_start;
        u64 hw_overhead = 1000;

        s64 refund = (s64)(host_processing + hw_overhead) - (target_cost + jitter);
        
        *offset -= refund;

        ctx->vmcb->control.tsc_offset = *offset;
        ctx->vmcb->control.clean = VMCB_CLEAN_STABLE;
        
        *p_last_tsc = rdtsc();
        *p_last_rip = current_rip;

        vmrun_with_regs(ctx->vmcb_pa, &regs);
        host_start = rdtsc();

        local_irq_restore(flags);
        preempt_enable();
    }

    pr_err("[VMEXIT] Max iterations (%d) exceeded\n", VMEXIT_MAX_ITERATIONS);
    ret = -ELOOP;

out:
    pr_info("[VMEXIT] Exited after %d iterations\n",
            VMEXIT_MAX_ITERATIONS - iter - 1);
    return ret;
}
