// SPDX-License-Identifier: GPL-2.0-only
/*
 * VMEXIT Dispatch Loop (V4.1 Stealth)
 *
 * Full VMEXIT handler with:
 *  - CPUID stealth (hypervisor bit cleared, vendor leaves hidden)
 *  - MSR emulation (TSC compensation, pass-through)
 *  - I/O port blocking (PIT, ACPI PM Timer)
 *  - Per-CPU TSC compensation integrated into the loop
 *  - VMCB clean bits for minimal timing jitter
 */

#include "ring_minus_one.h"
#include "svm_trace.h"
#include "svm_decode.h"
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/sched/signal.h>

/* AMD NPF ExitCode and info1 flags */
#define SVM_EXIT_NPF 0x400
#define NPF_INFO1_PRESENT (1ULL << 0)
#define NPF_INFO1_WRITE   (1ULL << 1)
#define NPF_INFO1_USER    (1ULL << 2)
#define NPF_INFO1_RSV     (1ULL << 3)
#define NPF_INFO1_EXECUTE (1ULL << 4)  /* Phase 18: NX violation */

/* AMD VMCB exception intercept: #DB = vector 1 */
#define EXCEPT_DB_BIT (1U << 1)

/* Guest RFLAGS Trap Flag for MTF single-step */
#define RFLAGS_TF (1ULL << 8)

/* State is now tracked per process in ctx->pending_rearm_gpa */

#define VMEXIT_MAX_ITERATIONS 100000

/* ═══════════════════════════════════════════════════════════════════════════
 *  Kill Switch — Matrix'in "Altın Çıkışı"
 *
 *  Guest RAX + RBX magic pattern ile hypervisor'dan acil çıkış.
 *  Geliştirici güvenlik ağı: sonsuz döngü veya #PF ping-pong'da
 *  makineyi resetlemek yerine temiz çıkış sağlar.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define KILL_SWITCH_RAX  0xDEADBEEFDEADBEEFULL
#define KILL_SWITCH_RBX  0x1337133713371337ULL

/* Ping-Pong Guard: ardışık kernel #PF re-injection limiti */
#define KERNEL_PF_REINJECT_MAX 256

/*
 * NPT identity map physical limit. Must match the value passed to
 * npt_build_identity_map() in main.c. GPA outside this range is
 * never legitimate and indicates a confused or malicious guest.
 */
#define NPT_PHYS_LIMIT (1ULL << 36) /* 64 GB */

/*
 * TSC Drift Guard: Maximum compensation per single #NPF exit.
 * ~10ms at 3GHz = 30,000,000 cycles. If hypervisor somehow
 * spends more than this in a single NPF (impossible normally),
 * we cap to prevent Clock Drift panics from TCP timestamps,
 * RTC desync, or Windows CLOCK_WATCHDOG_TIMEOUT.
 */
#define TSC_COMP_MAX_DELTA (30000000ULL)

/* ═══════════════════════════════════════════════════════════════════════════
 *  TSC Jitter PRNG — Anti Timing Analysis
 *
 *  Without jitter: every CPUID takes exactly N cycles → detected as emulated.
 *  With jitter: Gaussian-like noise makes timing look like real hardware
 *  (cache miss, pipeline stall, branch misprediction variance).
 *
 *  Uses a fast 64-bit LCG (Linear Congruential Generator).
 * ═══════════════════════════════════════════════════════════════════════════
 */

static DEFINE_PER_CPU(u64, jitter_state);

static inline u64 tsc_jitter(u64 min, u64 max)
{
	u64 *state = this_cpu_ptr(&jitter_state);

	if (!*state)
		*state = 0x5DEECE66DULL ^ rdtsc();

	/* LCG: state = state * 6364136223846793005 + 1442695040888963407 */
	*state = *state * 6364136223846793005ULL + 1442695040888963407ULL;

	/* Defensive: prevent UB if caller passes min > max */
	if (unlikely(min >= max))
		return min;

	return min + ((*state >> 33) % (max - min + 1));
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CPUID Handler — Anti-Detection Core
 *
 *  CPUID.1:ECX[31] = hypervisor present bit → cleared
 *  CPUID.0x40000000-0x4FFFFFFF = hypervisor leaves → zeroed
 *  All other leaves: native pass-through via host cpuid
 * ═══════════════════════════════════════════════════════════════════════════
 */

/*
 * Securely translate a Guest Physical Address (GPA) to a Host Physical 
 * Address (HPA) by walking the NPT map.
 */
static u64 npt_get_hpa(struct npt_context *ctx, u64 gpa)
{
	u64 *pml4 = ctx->pml4;
	int pml4i = (gpa >> 39) & 0x1FF;
	int pdpti = (gpa >> 30) & 0x1FF;
	int pdi   = (gpa >> 21) & 0x1FF;
	u64 pdpt_phys, *pdpt, pd_phys, *pd, pde, hpa_base;

	if (!pml4) return 0;
	
	/* 1. PML4 -> PDPT */
	if (!(pml4[pml4i] & 1)) return 0; /* Present bit check */
	pdpt_phys = pml4[pml4i] & 0x000FFFFFFFFFF000ULL; /* NX (bit 63) ve reserved bit mask */
	if (!pdpt_phys || !pfn_valid(pdpt_phys >> PAGE_SHIFT)) return 0;
	pdpt = (u64 *)phys_to_virt(pdpt_phys); /* Pointer cast aritmetiği koruması */

	/* 2. PDPT -> PD */
	if (!(pdpt[pdpti] & 1)) return 0;
	pd_phys = pdpt[pdpti] & 0x000FFFFFFFFFF000ULL;
	if (!pd_phys || !pfn_valid(pd_phys >> PAGE_SHIFT)) return 0;
	pd = (u64 *)phys_to_virt(pd_phys);

	/* 3. PD -> PTE veya 2MB Page */
	pde = pd[pdi];
	if (!(pde & 1)) return 0; /* Present bit = 0 (sayfa NPT'de yok) */

	/* Active SVM Identity Map currently uses exclusively 2MB pages */
	if (pde & (1ULL << 7)) { /* PSE (Page Size Extension) for 2MB pages */
		hpa_base = pde & 0x000FFFFFFFFE0000ULL; /* 2MB base mask (Bits 51:21) */
		return hpa_base | (gpa & ((2ULL << 20) - 1)); /* Kalan 21 bit offset */
	} else {
		/* Fallback for 4KB pages in case the identity map gets rebuilt with them */
		int pti = (gpa >> 12) & 0x1FF;
		u64 pt_phys = pde & 0x000FFFFFFFFFF000ULL;
		u64 *pt, pte;
		
		if (!pt_phys || !pfn_valid(pt_phys >> PAGE_SHIFT)) return 0;
		pt = (u64 *)phys_to_virt(pt_phys);
		pte = pt[pti];
		if (!(pte & 1)) return 0;
		return (pte & 0x000FFFFFFFFFF000ULL) | (gpa & 0xFFF); /* 4KB offset */
	}
}

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

static void handle_msr(struct vmcb *vmcb, struct guest_regs *regs)
{
	u32 msr_num = (u32)regs->rcx;
	bool is_write = vmcb->control.exit_info_1 & 1;
	u64 val;

	/* Beklenmeyen MSR istekleri 'default' case ile maskelenir ve safe olarak 0
	 * dönülür, AMD'nin gelecekteki geçerli MSR range'lerini kestiğimiz için burada
	 * manuel #GP enjeksiyonundan vazgeçildi.
	 */

	if (is_write) {
		u64 wval = (regs->rdx << 32) | (vmcb->save.rax & 0xFFFFFFFFULL);

		switch (msr_num) {
		/*
		 * [PHASE 19] Thread Doğumu Tespiti (Pure VMI)
		 * OS yeni thread için TLS alanı ayarlarken WRMSR FS/GS_BASE
		 * yazar. Bu yazma işlemi #VMEXIT üretir ve burada yakalanır.
		 * Yazma işlemini native olarak gerçekleştiriyoruz (TLS bozulmasın)
		 * ancak olayı telemetry ring buffer'a logluyoruz.
		 *
		 * NOT: SWAPGS de MSR_GS_BASE üzerinden geçer, bu sayede
		 * user→kernel geçişleri de otomatik olarak yakalanır.
		 */
		case 0xC0000100: /* MSR_FS_BASE */
		case 0xC0000101: /* MSR_GS_BASE */
		case 0xC0000102: /* MSR_KERNEL_GS_BASE */
			pr_info_ratelimited("[PHASE19] Thread TLS write: MSR 0x%x = 0x%llx (PID context CR3=0x%llx)\n",
					   msr_num, wval, vmcb->save.cr3);
			/* Native execute: TLS/SWAPGS bozulmamalı */
			wrmsrq(msr_num, wval);
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
		/*
		 * EAC reads these to detect extra micro-ops from VMEXIT.
		 * Return real value — the overhead is hidden by TSC compensation.
		 * These counters are hardware and can't be easily faked,
		 * but intercepting prevents cross-correlation attacks.
		 */
		if (rdmsrq_safe(msr_num, &val))
			val = 0;
		break;

	case 0x38D: /* IA32_PERF_FIXED_CTR_CTRL */
	case 0x38F: /* IA32_PERF_GLOBAL_CTRL */
		/* Pass through reads, block writes (handled in is_write above) */
		if (rdmsrq_safe(msr_num, &val))
			val = 0;
		break;

	/* ── BTS: Block Branch Trace Store ── */
	case 0x1D9: /* IA32_DEBUGCTL */
		/*
		 * BTS (Branch Trace Store) can record VMRUN branch target.
		 * We intercept reads to return value with BTS bits cleared,
		 * and intercept writes to silently ignore BTS enable.
		 */
		if (rdmsrq_safe(msr_num, &val))
			val = 0;
		val &= ~(3ULL);	     /* Clear bits 0-1 (LBR, BTF) */
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

	pr_info_once("[VMEXIT] First userspace thread entered Matrix.\n");

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

	vmrun_with_regs(ctx->vmcb_pa, regs);

	/*
	 * CRITICAL: Do NOT reload FS/GS selectors!
	 * 'mov %%gs' zeroes GS_BASE. Write MSRs directly.
	 */
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

	switch (exit_code) {
	case SVM_EXIT_CPUID: {
		u32 leaf = (u32)ctx->vmcb->save.rax;

		if (leaf >= 0x0B)
			target_cost = -100;
		else if (tsc_since_last_exit < 15000 && rip_diff < 32) {
			target_cost = 30;
			jitter = 0;
		} else {
			target_cost = 80;
		}
		break;
	}
	case SVM_EXIT_MSR:
		target_cost = 120;
		break;
	case SVM_EXIT_IOIO:
		target_cost = 250;
		break;
	}

	/* ── Dispatch (Host İşlemleri) ── */
	switch (exit_code) {
	case SVM_EXIT_CPUID:
		handle_cpuid(ctx->vmcb, regs);
		break;

	case SVM_EXIT_HLT:
		pr_info("[VMEXIT] Guest HLT — normal exit (0x78)\n");
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
		u64 gpa = ctx->vmcb->control.exit_info_2;
		u64 info1 = ctx->vmcb->control.exit_info_1;

		u64 npf_entry_tsc = rdtsc(); /* TSC Compensation: Zamanlayıcıyı başlat */

		/*
		 * Kill Switch 2: NPF Infinite Loop Guard
		 * Eğer aynı GPA üzerinde sürekli NPF hatası alıyorsak (decoder bypass
		 * veya forward progress yoksa), sistemi kilitlenmekten (hard-lock) kurtar.
		 */
		if (gpa == ctx->last_npf_gpa) {
			ctx->npf_loop_count++;
			if (ctx->npf_loop_count > 10000) {
				pr_emerg("[MATRIX] *** KILL SWITCH: NPF INFINITE LOOP at GPA 0x%llx! Ejecting. ***\n", gpa);
				ctx->npf_loop_count = 0;
				ret = 1;
				break;
			}
		} else {
			ctx->last_npf_gpa = gpa;
			ctx->npf_loop_count = 0;
		}

		/*
		 * ═══════════════════════════════════════════════════════════════
		 * Phase 18 [IF]: Surgical NX Execute-Fault Handler (Hardened)
		 *
		 * VMP decrypted bir sayfayı execute etmeye kalktığında
		 * NPT'deki NX biti #NPF üretir. Sadece izlenen (watched)
		 * sayfalar bu dallanmaya düşer.
		 *
		 * TSC COMPENSATION: Her #NPF'de hypervisor'da geçen süre
		 * hesaplanır ve vmcb->control.tsc_offset'ten düşülür.
		 * Guest RDTSC okuduğunda zamanın büküldüğünü göremez.
		 *
		 * INVLPGA: Full TLB flush yerine sadece hedef ASID+GPA
		 * çifti invalidate edilir. O(1) maliyet.
		 * ═══════════════════════════════════════════════════════════════
		 */
		if (info1 & NPF_INFO1_EXECUTE) {
			u32 watch_flags = npt_hook_is_watched(gpa);

			if (watch_flags & NPT_WATCH_NX) {
				/* GPA güvenlik kontrolü */
				if (gpa >= NPT_PHYS_LIMIT || !pfn_valid(gpa >> PAGE_SHIFT))
					break;

				/* Telemetry: Execute trap logla */
				void *hva = phys_to_virt(gpa & PAGE_MASK);

				svm_trace_emit_dirty(ctx->vmcb->save.cr3,
						     ctx->vmcb->save.rip,
						     gpa & PAGE_MASK, hva);

				/*
				 * Phase 21: Instruction Decoder (Split-View)
				 * Before lifting NX and exposing the page, try to decode and emulate 
				 * register-only instructions natively from host memory.
				 *
				 * SAFARI / BOUNDARY CHECK: gpa is Guest Physical, we must precisely 
				 * map it to Host Physical, and handle cross-page instruction fetches.
				 */
				{
					u8 insn_buf[15] = {0};
					u64 hpa1 = npt_get_hpa(&ctx->npt, gpa);

					if (hpa1 && pfn_valid(hpa1 >> PAGE_SHIFT)) {
						void *hva1 = phys_to_virt(hpa1);
						size_t bytes_in_page = PAGE_SIZE - (hpa1 & ~PAGE_MASK);
						size_t read_len1 = (bytes_in_page < 15) ? bytes_in_page : 15;

						memcpy(insn_buf, hva1, read_len1);

						/* Handle instructions crossing a physical page boundary safely */
						if (read_len1 < 15) {
							u64 gpa2 = gpa + read_len1;
							u64 hpa2 = npt_get_hpa(&ctx->npt, gpa2);
							
							if (hpa2 && pfn_valid(hpa2 >> PAGE_SHIFT)) {
								void *hva2 = phys_to_virt(hpa2);
								memcpy(insn_buf + read_len1, hva2, 15 - read_len1);
							}
						}

						/* Attempt hypervisor-level emulation */
						u32 decode_result = svm_decode_insn(insn_buf, &ctx->gregs, &ctx->vmcb->save);
						u32 insn_len = decode_result & DECODE_LEN_MASK;

						if ((decode_result & DECODE_ACTION_EMULATED) && insn_len > 0) {
							/* Successfully emulated register operation! No NX lift needed. */
							if (!(decode_result & DECODE_ACTION_BRANCH))
								ctx->vmcb->save.rip += insn_len;

							/* Telemetry trace (0, 0 since it's just sequential emulation unless branch) */
							svm_trace_emit_lbr(ctx->vmcb->save.cr3, ctx->vmcb->save.rip, 0, 0);

							/* Enforce TSC Compensation / Drift Control before seamless resume */
							u64 npf_exit_tsc = rdtsc();
							u64 hv_delta = npf_exit_tsc - npf_entry_tsc;
							if (hv_delta > TSC_COMP_MAX_DELTA)
								hv_delta = TSC_COMP_MAX_DELTA;
							
							ctx->vmcb->control.tsc_offset -= hv_delta;
							ctx->vmcb->control.clean &= ~VMCB_CLEAN_TSC;

							break; /* Resume guest transparently */
						}
					}
				}

				/* NPT'den geçici olarak NX'i kaldır (execute izni ver) - Fallback */
				{
					u64 *pml4 = ctx->npt.pml4;
					int pml4i = (gpa >> 39) & 0x1FF;
					int pdpti = (gpa >> 30) & 0x1FF;
					int pdi = (gpa >> 21) & 0x1FF;

					u64 pdpt_phys = pml4[pml4i] & ~0xFFFULL;

					if (!pdpt_phys || !pfn_valid(pdpt_phys >> PAGE_SHIFT))
						goto skip_nx_rearm;
					u64 *pdpt = phys_to_virt(pdpt_phys);

					u64 pd_phys = pdpt[pdpti] & ~0xFFFULL;

					if (!pd_phys || !pfn_valid(pd_phys >> PAGE_SHIFT))
						goto skip_nx_rearm;
					u64 *pd = phys_to_virt(pd_phys);

					pd[pdi] &= ~NPT_NX; /* Geçici execute izni */
				}

				/*
				 * INVLPGA: Sadece bu ASID+GPA için TLB entry'sini düşür.
				 * Full flush (TLB_CTL=1) yapmak yerine cerrahi invalidation.
				 *
				 * NOT: INVLPGA sadece yerel çekirdeğin TLB'sini temizler.
				 * Multi-core senaryoda stale TLB riski var. Ancak Matrix
				 * süreci CPU 0'a pinli olduğu için (svm_chardev.c) bu
				 * güvenli. Faz 19'da multi-core desteği gelirse INVLPGB
				 * veya IPI-flush mekanizmasına geçilmeli.
				 */
				asm volatile("invlpga" :: "a"(gpa & PAGE_MASK),
					     "c"((u32)ctx->vmcb->control.asid));

skip_nx_rearm:
				ctx->pending_rearm_gpa = gpa & PAGE_MASK;
				ctx->pending_rearm_nx = 1; /* Instruct #DB handler to lift EXACTLY NX */
				ctx->vmcb->save.rflags |= RFLAGS_TF;
				ctx->vmcb->control.intercepts[INTERCEPT_EXCEPTION_OFFSET >> 5] |=
				    EXCEPT_DB_BIT;
				ctx->vmcb->control.clean &= ~(VMCB_CLEAN_NP | VMCB_CLEAN_INTERCEPTS);
			}

			/* TSC Compensation: Hypervisor'da geçen süreyi Guest TSC'den sil */
			{
				u64 npf_exit_tsc = rdtsc();
				u64 hv_delta = npf_exit_tsc - npf_entry_tsc;

				/* Drift Guard: Üst sınır aşılırsa cap uygula */
				if (hv_delta > TSC_COMP_MAX_DELTA)
					hv_delta = TSC_COMP_MAX_DELTA;

				ctx->vmcb->control.tsc_offset -= hv_delta;
				ctx->vmcb->control.clean &= ~VMCB_CLEAN_TSC;
			}
			break;
		}

		if (info1 & NPF_INFO1_WRITE) {
			/*
			 * SECURITY: Validate GPA is within our identity map.
			 */
			if (gpa >= NPT_PHYS_LIMIT)
				break;

			if (!pfn_valid(gpa >> PAGE_SHIFT))
				break;

			void *hva = phys_to_virt(gpa & PAGE_MASK);

			svm_trace_emit_dirty(ctx->vmcb->save.cr3, ctx->vmcb->save.rip,
					     gpa & PAGE_MASK, hva);

			{
				u64 *pml4 = ctx->npt.pml4;
				int pml4i = (gpa >> 39) & 0x1FF;
				int pdpti = (gpa >> 30) & 0x1FF;
				int pdi = (gpa >> 21) & 0x1FF;

				u64 pdpt_phys = pml4[pml4i] & ~0xFFFULL;

				if (!pdpt_phys || !pfn_valid(pdpt_phys >> PAGE_SHIFT))
					goto skip_rearm;
				u64 *pdpt = phys_to_virt(pdpt_phys);

				u64 pd_phys = pdpt[pdpti] & ~0xFFFULL;

				if (!pd_phys || !pfn_valid(pd_phys >> PAGE_SHIFT))
					goto skip_rearm;
				u64 *pd = phys_to_virt(pd_phys);

				pd[pdi] |= NPT_WRITE;
			}

			/*
			 * INVLPGA: Cerrahi TLB invalidation (Write-fault path)
			 */
			asm volatile("invlpga" :: "a"(gpa & PAGE_MASK),
				     "c"((u32)ctx->vmcb->control.asid));

skip_rearm:
			ctx->pending_rearm_gpa = gpa & PAGE_MASK;
			ctx->pending_rearm_nx = 0; /* Instruct #DB handler to restore NPT_WRITE, not NPT_NX */
			ctx->vmcb->save.rflags |= RFLAGS_TF;
			ctx->vmcb->control.intercepts[INTERCEPT_EXCEPTION_OFFSET >> 5] |=
			    EXCEPT_DB_BIT;
			ctx->vmcb->control.clean &= ~(VMCB_CLEAN_NP | VMCB_CLEAN_INTERCEPTS);

			/* TSC Compensation: Write-fault path */
			{
				u64 npf_exit_tsc = rdtsc();
				u64 hv_delta = npf_exit_tsc - npf_entry_tsc;

				/* Drift Guard: Üst sınır aşılırsa cap uygula */
				if (hv_delta > TSC_COMP_MAX_DELTA)
					hv_delta = TSC_COMP_MAX_DELTA;

				ctx->vmcb->control.tsc_offset -= hv_delta;
				ctx->vmcb->control.clean &= ~VMCB_CLEAN_TSC;
			}
		}
		break;
	}

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
					pr_info("[PROXY] Hedef exit_group() (%llu) cagirdi! Matrix kapaniyor.\n",
						syscall_nr);
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

		pr_err("[SVM_PANIC] Genuine #UD Invalid Opcode at RIP: 0x%llx\n",
		       ctx->vmcb->save.rip);
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
		if (ctx->vmcb->save.rax == KILL_SWITCH_RAX &&
		    regs->rbx == KILL_SWITCH_RBX) {
			pr_emerg("[MATRIX] *** KILL SWITCH TRIGGERED *** Ejecting PID %d\n",
				 current->pid);
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
		if (fault_va >= TASK_SIZE_MAX) {
			/* Ping-Pong Guard: ardışık re-injection sayacı */
			ctx->kernel_pf_count++;
			if (ctx->kernel_pf_count > KERNEL_PF_REINJECT_MAX) {
				pr_err("[MATRIX] PING-PONG GUARD: %u consecutive kernel #PFs! Ejecting.\n",
				       ctx->kernel_pf_count);
				ctx->kernel_pf_count = 0;
				ret = 1;
				break;
			}

			ctx->vmcb->control.event_inj =
			    SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT |
			    SVM_EVTINJ_VALID_ERR | 14;
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
					pr_err("[MATRIX_ESCAPE] CoW Yazma Hatasi at 0x%llx. Ejecting.\n",
					       fault_va);
					ret = 1;
					break;
				}
			}
			/* Page is now physically backed by Host Kernel. Re-enter VMRUN! */
			ret = 0;
			break;
		}

		/* Real Segmentation Fault / Invalid Memory Access */
		pr_err("[MATRIX_ESCAPE] Fatal #PF at RIP=0x%llx CR2=0x%llx (err=%llx). Ejecting.\n",
		       ctx->vmcb->save.rip, fault_va, error_code);
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

				u64 pdpt_phys = pml4[pml4i] & ~0xFFFULL;

				if (pdpt_phys && pfn_valid(pdpt_phys >> PAGE_SHIFT)) {
					u64 *pdpt = phys_to_virt(pdpt_phys);
					u64 pd_phys = pdpt[pdpti] & ~0xFFFULL;

					if (pd_phys && pfn_valid(pd_phys >> PAGE_SHIFT)) {
						u64 *pd = phys_to_virt(pd_phys);

						/* Phase 21: Correctly re-arm NX or Write based on fault type */
						if (ctx->pending_rearm_nx) {
							pd[pdi] |= NPT_NX;     /* Execute korumasını geri koy */
							ctx->pending_rearm_nx = 0;
						} else {
							pd[pdi] &= ~NPT_WRITE; /* Write korumasını geri koy */
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
		pr_err("[VMEXIT] VMEXIT_INVALID — VMCB misconfigured!\n");
		ret = -EIO;
		goto out;

	default:
		pr_warn("[VMEXIT] Unhandled exit: 0x%llx at RIP=0x%llx\n", exit_code,
			ctx->vmcb->save.rip);
		ret = -EIO;
		goto out;
	}

	/* ── Phase 2: LBR Chronological Drain ── */
	pr_info_once("[VMEXIT] Telemetry drain reached (exit_code=0x%llx, ret=%d)\n", exit_code, ret);
	svm_trace_emit_lbr(ctx->vmcb->save.cr3, ctx->vmcb->save.rip, ctx->vmcb->save.br_from, ctx->vmcb->save.br_to);

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
		ctx->vmcb->control.clean = VMCB_CLEAN_STABLE;

		*p_last_tsc = rdtsc();
		*p_last_rip = current_rip;
	}

out:
	return ret;
}
