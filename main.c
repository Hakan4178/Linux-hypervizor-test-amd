// SPDX-License-Identifier: GPL-2.0-only
/*
 * Module Init/Exit + VMCB Prepare (V6.7 Stealth)
 *
 *
 */

#include "ring_minus_one.h"
#include "svm_trace.h"
#include <asm/cpufeature.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/kthread.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hakan");
MODULE_DESCRIPTION("AMD-V SVM Ring -1 Unified Engine V4.0");
MODULE_IMPORT_NS("KVM_AMD");

/* ═══════════════════════════════════════════════════════════════════════════
 *  Singleton Contexts (Local, passed explicitly to others or via
 * ptr)
 * ═══════════════════════════════════════════════════════════════════════════
 */

static struct svm_context svm_ctx = {0};
static struct snap_context snap_ctx = {0};

/* Removed: guest_kthread loop */

struct svm_context *g_svm = &svm_ctx;
struct snap_context *g_snap = &snap_ctx;

/* ═══════════════════════════════════════════════════════════════════════════
 *  MSRPM Adres Makroları (AMD APM Vol.2 §15.11)
 *
 *  MSRPM Layout (toplam 12KB = 3 bölge × 2KB eşleme × 2 bit/MSR):
 *    Bölge 0: MSR 0x0000_0000 – 0x0000_1FFF  →  offset 0x0000
 *    Bölge 1: MSR 0xC000_0000 – 0xC000_1FFF  →  offset 0x0800
 *    Bölge 2: MSR 0xC001_0000 – 0xC001_1FFF  →  offset 0x1000
 *
 *  Her MSR için 2 bit: bit0=RDMSR intercept, bit1=WRMSR intercept
 * ═══════════════════════════════════════════════════════════════════════════
 */
#define MSRPM_BYTE_OFF(base, msr) ((base) + ((msr) & 0x1FFF) * 2 / 8)
#define MSRPM_BIT_POS(msr) (((msr) & 0x1FFF) * 2 % 8)

/* Bölge base offset'leri */
#define MSRPM_BASE_LOW 0x0000  /* 0x0000_0000 – 0x0000_1FFF */
#define MSRPM_BASE_C000 0x0800 /* 0xC000_0000 – 0xC000_1FFF */
#define MSRPM_BASE_C001 0x1000 /* 0xC001_0000 – 0xC001_1FFF */

/* Kısayol: rdmsr intercept (bit 0) */
#define MSRPM_SET_RD(pm, base, msr)                                                                \
	((pm)[MSRPM_BYTE_OFF(base, msr)] |= (1 << MSRPM_BIT_POS(msr)))

/* Kısayol: rdmsr + wrmsr intercept (bit 0 + bit 1) */
#define MSRPM_SET_RW(pm, base, msr)                                                                \
	((pm)[MSRPM_BYTE_OFF(base, msr)] |= (3 << MSRPM_BIT_POS(msr)))

/* ═══════════════════════════════════════════════════════════════════════════
 *  VMCB Prepare — V4.0 Stealth Intercepts
 * ═══════════════════════════════════════════════════════════════════════════
 */

/*
 * vmcb_prepare_npt - VMCB'yi NPT tabanlı çalışma için yapılandır
 * @vmcb: yapılandırılacak VMCB (çağıran tahsis eder)
 * @g_rip: başlangıç guest instruction pointer
 * @g_rsp: başlangıç guest stack pointer
 * @g_cr3: guest CR3 (0 = mevcut host CR3 kullan)
 * @npt: NPT context (NULL = NPT devre dışı)
 *
 * V4.0 Stealth: CPUID intercept, per-CPU TSC, ASID-only TLB,
 * full timer I/O coverage, expanded MSR intercepts.
 */
int vmcb_prepare_npt(struct svm_context *ctx, u64 g_rip, u64 g_rsp, u64 g_cr3)
{
	struct vmcb *vmcb = ctx->vmcb;
	struct npt_context *npt = &ctx->npt;
	u64 efer_val, cr0, cr4, rflags, msr_val;
	unsigned long cr3;
	u16 cs, ds, ss, es, fs, gs, tr;
	struct desc_ptr gdtr, idtr;
	u64 fs_base, gs_base;

	memset(vmcb, 0, sizeof(*vmcb));

	/* Read host state */
	rdmsrl(MSR_EFER, efer_val);
	cr0 = native_read_cr0();
	asm volatile("mov %%cr3, %0" : "=r"(cr3));
	cr4 = native_read_cr4();
	asm volatile("pushf; pop %0" : "=r"(rflags));

	asm volatile("mov %%cs, %0" : "=r"(cs));
	asm volatile("mov %%ds, %0" : "=r"(ds));
	asm volatile("mov %%ss, %0" : "=r"(ss));
	asm volatile("mov %%es, %0" : "=r"(es));
	asm volatile("mov %%fs, %0" : "=r"(fs));
	asm volatile("mov %%gs, %0" : "=r"(gs));
	asm volatile("str  %0" : "=r"(tr));
	asm volatile("sgdt %0" : "=m"(gdtr));
	asm volatile("sidt %0" : "=m"(idtr));
	rdmsrl(MSR_FS_BASE, fs_base);
	rdmsrl(MSR_GS_BASE, gs_base);

	/* ── Intercepts ── */

	/* VMRUN (mandatory) */
	vmcb->control.intercepts[INTERCEPT_VMRUN >> 5] |= (1U << (INTERCEPT_VMRUN & 31));
	/* HLT */
	vmcb->control.intercepts[INTERCEPT_HLT >> 5] |= (1U << (INTERCEPT_HLT & 31));
	/* CPUID — uniform latency, prevent timing fingerprint */
	vmcb->control.intercepts[INTERCEPT_CPUID >> 5] |= (1U << (INTERCEPT_CPUID & 31));

	/* MSR and IO interception (mandatory for MSRPM/IOPM usage) */
	vmcb->control.intercepts[INTERCEPT_MSR_PROT >> 5] |= (1U << (INTERCEPT_MSR_PROT & 31));
	vmcb->control.intercepts[INTERCEPT_IOIO_PROT >> 5] |= (1U << (INTERCEPT_IOIO_PROT & 31));

	/* RDTSCP */
#ifdef INTERCEPT_RDTSCP
	vmcb->control.intercepts[INTERCEPT_RDTSCP >> 5] |= (1U << (INTERCEPT_RDTSCP & 31));
#endif

	/* ── Exception Intercepts ──
	 * #UD (6): EFER.SCE kapalı olduğu için SYSCALL → #UD üretir.
	 *          Bu intercepti koymazsak CPU, Guest IDT'ye dalar → SMEP panic.
	 * #PF (14): NPF zaten var ama guest-level #PF'i de yakala (güvenlik ağı).
	 */
	vmcb->control.intercepts[INTERCEPT_EXCEPTION_OFFSET >> 5] |= (1U << 6);	 /* #UD */
	vmcb->control.intercepts[INTERCEPT_EXCEPTION_OFFSET >> 5] |= (1U << 14); /* #PF */

	/* ── Hardware Interrupt Intercepts (Host Watchdog / Soft-Lockup Protection)
	 * ── V_INTR_MASKING aktifken Host'a gelen fiziksel donanım kesmeleri (Timer,
	 * NMI) doğrudan #VMEXIT (SVM_EXIT_INTR) üretir. Böylece Host sistemi felç
	 * olmaz!
	 */
	vmcb->control.intercepts[INTERCEPT_INTR >> 5] |= (1U << (INTERCEPT_INTR & 31));
	vmcb->control.intercepts[INTERCEPT_NMI >> 5] |= (1U << (INTERCEPT_NMI & 31));
	vmcb->control.intercepts[INTERCEPT_SMI >> 5] |= (1U << (INTERCEPT_SMI & 31));
	vmcb->control.int_ctl |= V_INTR_MASKING_MASK;

	/* ── MSRPM V5.0: Macro-Based Addressing (AMD APM Vol.2 §15.11) ── */
	if (ctx->msrpm_va) {
		u8 *msrpm = (u8 *)ctx->msrpm_va;

		/* ── Bölge 0: MSR 0x0000xxxx (Low MSRs) ── */
		MSRPM_SET_RD(msrpm, MSRPM_BASE_LOW, 0x10);  /* IA32_TSC: rdmsr */
		MSRPM_SET_RD(msrpm, MSRPM_BASE_LOW, 0xE7);  /* IA32_MPERF: rdmsr */
		MSRPM_SET_RD(msrpm, MSRPM_BASE_LOW, 0xE8);  /* IA32_APERF: rdmsr */
		MSRPM_SET_RD(msrpm, MSRPM_BASE_LOW, 0x176); /* IA32_SYSENTER_EIP: rdmsr */
		MSRPM_SET_RW(msrpm, MSRPM_BASE_LOW, 0x1D9); /* IA32_DEBUGCTL: rd+wr (BTS block) */
		MSRPM_SET_RD(msrpm, MSRPM_BASE_LOW, 0x309); /* IA32_FIXED_CTR0: rdmsr */
		MSRPM_SET_RD(msrpm, MSRPM_BASE_LOW, 0x30A); /* IA32_FIXED_CTR1: rdmsr */
		MSRPM_SET_RD(msrpm, MSRPM_BASE_LOW, 0x30B); /* IA32_FIXED_CTR2: rdmsr */
		MSRPM_SET_RW(msrpm, MSRPM_BASE_LOW, 0x38D); /* IA32_PERF_FIXED_CTR_CTRL: rd+wr */
		MSRPM_SET_RW(msrpm, MSRPM_BASE_LOW, 0x38F); /* IA32_PERF_GLOBAL_CTRL: rd+wr */

		/* ── Bölge 1: MSR 0xC000xxxx ── */
		MSRPM_SET_RW(msrpm, MSRPM_BASE_C000, 0x81);  /* STAR: rd+wr */
		MSRPM_SET_RW(msrpm, MSRPM_BASE_C000, 0x82);  /* LSTAR: rd+wr */
		MSRPM_SET_RD(msrpm, MSRPM_BASE_C000, 0x103); /* TSC_AUX: rdmsr */

		/* ── Bölge 2: MSR 0xC001xxxx ── */
		MSRPM_SET_RD(msrpm, MSRPM_BASE_C001,
			     0x15); /* K8_HWCR (0xC0010015): SVME_LOCK spoofing */
		MSRPM_SET_RD(msrpm, MSRPM_BASE_C001,
			     0x114); /* SVM_LOCK_KEY (0xC0010114): SVM hiding */
	}

	/* ── IOPM: Timer I/O port coverage ── */
	if (ctx->iopm_va) {
		u8 *iopm = (u8 *)ctx->iopm_va;

		/* PIT: 0x40-0x43 */
		iopm[0x40 / 8] |= (1 << (0x40 % 8));
		iopm[0x41 / 8] |= (1 << (0x41 % 8));
		iopm[0x42 / 8] |= (1 << (0x42 % 8));
		iopm[0x43 / 8] |= (1 << (0x43 % 8));
		/* ACPI PM Timer: 0x808-0x80B */
		iopm[0x808 / 8] |= (1 << (0x808 % 8));
		iopm[0x809 / 8] |= (1 << (0x809 % 8));
		iopm[0x80A / 8] |= (1 << (0x80A % 8));
		iopm[0x80B / 8] |= (1 << (0x80B % 8));
	}

	vmcb->control.msrpm_base_pa = ctx->msrpm_pa;
	vmcb->control.iopm_base_pa = ctx->iopm_pa;

	/* ASID-only isolation, no TLB flush penalty */
	vmcb->control.asid = 2;
	vmcb->control.tlb_ctl = 0;

	vmcb->control.virt_ext |= LBR_CTL_ENABLE_MASK; // LBR Virtualization (save/restore)

	/*
	 * Enable actual LBR recording in the guest.
	 * LBRV alone only saves/restores LBR state on VMRUN/VMEXIT.
	 * We must also set DBGCTL.LBR (bit 0) to start branch recording.
	 * After VMEXIT, br_from/br_to in the VMCB save area will contain
	 * the guest's last branch taken before the exit.
	 */
	vmcb->save.dbgctl = 1; /* LBR enable */

	/* First VMRUN: clean=0 forces full load. Subsequent runs use STABLE. */
	vmcb->control.clean = 0;

	/* NPT configuration — Strengthened validation (Security Fix #2) */
	if (npt && npt->pml4_pa && IS_ALIGNED(npt->pml4_pa, PAGE_SIZE) &&
	    pfn_valid(npt->pml4_pa >> PAGE_SHIFT) && npt->pml4 != NULL) {
		vmcb->control.nested_ctl = 1;
		vmcb->control.nested_cr3 = npt->pml4_pa;
		pr_info("[VMCB] NPT enabled, nested_cr3=0x%llx\n", (u64)npt->pml4_pa);
	} else {
		pr_err("[VMCB] CRITICAL: Invalid NPT PML4 pa=%llx virt=%p. Aborting VMRUN.\n",
		       npt ? (u64)npt->pml4_pa : 0, npt ? npt->pml4 : NULL);
		vmcb->control.nested_ctl = 0;
		return -EINVAL; /* Do NOT allow VMRUN with broken page tables */
	}

	/* TSC offset — per-CPU */
	vmcb->control.tsc_offset = *this_cpu_ptr(&pcpu_tsc_offset);

	/* MSR Kopyalamaları: Host -> Guest */
	rdmsrl(MSR_STAR, msr_val);
	vmcb->save.star = msr_val;
	rdmsrl(MSR_LSTAR, msr_val);
	vmcb->save.lstar = msr_val;
	rdmsrl(MSR_CSTAR, msr_val);
	vmcb->save.cstar = msr_val;
	rdmsrl(MSR_SYSCALL_MASK, msr_val);
	vmcb->save.sfmask = msr_val;
	rdmsrl(MSR_KERNEL_GS_BASE, msr_val);
	vmcb->save.kernel_gs_base = msr_val;
	rdmsrl(MSR_FS_BASE, msr_val);
	vmcb->save.fs.base = msr_val;
	rdmsrl(MSR_GS_BASE, msr_val);
	vmcb->save.gs.base = msr_val;

	/* EFER Register - SVME Enable and Disable SCE (SYSCALL) to catch transitions
	 */
	rdmsrl(MSR_EFER, msr_val);
	vmcb->save.efer = (msr_val | EFER_SVME) & ~EFER_SCE;

	/* TR (Task Register) - Triple Fault Fix (Security Fix #3)
	 * 64-bit TSS descriptor = 16 byte (desc[0..3]), Intel/AMD SDM Vol.3 §7.2.3
	 */
	{
		u16 tr_sel;
		struct desc_ptr dt;

		native_store_gdt(&dt);
		asm volatile("str %0" : "=m"(tr_sel));
		vmcb->save.tr.selector = tr_sel;

		if (dt.address && tr_sel && (tr_sel + 15 <= dt.size)) {
			u8 *gdt = (u8 *)dt.address;
			u32 d0 = ((u32 *)(gdt + tr_sel))[0];
			u32 d1 = ((u32 *)(gdt + tr_sel))[1];
			u32 d2 =
			    ((u32 *)(gdt + tr_sel))[2]; /* upper 32-bit of base (64-bit mode) */

			/* Base: bits[15:0] from d0[31:16], bits[23:16] from d1[7:0],
			 * bits[31:24] from d1[31:24]
			 */
			u64 base = ((d0 >> 16) & 0xFFFF) | (((u64)(d1 & 0xFF)) << 16) |
				   (((u64)(d1 & 0xFF000000))) | (((u64)d2) << 32);

			/* Limit: bits[15:0] from d0[15:0], bits[19:16] from d1[19:16] */
			u32 limit = (d0 & 0xFFFF) | (d1 & 0x000F0000);

			if (d1 & (1 << 23)) /* Granularity */
				limit = (limit << 12) | 0xFFF;

			vmcb->save.tr.base = base;
			vmcb->save.tr.limit = limit;
		} else {
			pr_warn(
			    "[VMCB] TR selector invalid (sel=0x%x, gdt.addr=%lx, gdt.size=%u)\n",
			    tr_sel, dt.address, dt.size);
			vmcb->save.tr.base = 0;
			vmcb->save.tr.limit = 0xFFFF;
		}
		vmcb->save.tr.attrib = 0x0089; /* Type=0x9 (Available 64-bit TSS), P=1 */
	}

	/* ── Segment Registers (Ring 3 / CPL=3) ── */
	vmcb->save.cpl = 3; /* Matrix'te hedef User Mode'da koşmalı (SMEP engeli
			     * olmaması için)
			     */

	/* Gerçek Linux User Mode selector'ları kullan.
	 * Host CS=0x10 (kernel), ama Guest User CS=0x33 (__USER_CS) olmalı.
	 * 0x10 | 3 = 0x13 yaparsak geçersiz GDT girişine dallanır → #GP.
	 */
	vmcb->save.cs.selector = __USER_CS; /* 0x33 */
	vmcb->save.cs.attrib = 0x02FB;	    /* L=1, DPL=3, Type=0xB (Execute/Read) */
	vmcb->save.cs.limit = 0xFFFFFFFF;
	vmcb->save.cs.base = 0;

	vmcb->save.ds.selector = __USER_DS; /* 0x2B */
	vmcb->save.ds.attrib = 0x00F3;	    /* DPL=3, Type=0x3 (Read/Write) */
	vmcb->save.ds.limit = 0xFFFFFFFF;
	vmcb->save.ds.base = 0;

	vmcb->save.es.selector = __USER_DS;
	vmcb->save.es.attrib = 0x00F3;
	vmcb->save.es.limit = 0xFFFFFFFF;
	vmcb->save.es.base = 0;

	vmcb->save.ss.selector = __USER_DS;
	vmcb->save.ss.attrib = 0x00F3;
	vmcb->save.ss.limit = 0xFFFFFFFF;
	vmcb->save.ss.base = 0;

	vmcb->save.fs.selector = 0;
	vmcb->save.fs.attrib = 0x00F3;
	vmcb->save.fs.limit = 0xFFFFFFFF;
	vmcb->save.gs.selector = 0;
	vmcb->save.gs.attrib = 0x00F3;
	vmcb->save.gs.limit = 0xFFFFFFFF;
	vmcb->save.gs.base = gs_base;

	vmcb->save.gdtr.limit = gdtr.size;
	vmcb->save.gdtr.base = gdtr.address;
	vmcb->save.idtr.limit = idtr.size;
	vmcb->save.idtr.base = idtr.address;

	/* Control registers */
	vmcb->save.cr0 = cr0;
	vmcb->save.cr3 =
	    (g_cr3 && pfn_valid(g_cr3 >> PAGE_SHIFT)) ? g_cr3 : (cr3 & 0xFFFFFFFFFFFFF000ULL);
	vmcb->save.cr4 = cr4;
	/* EFER zaten satır 233'te doğru ayarlandı (SVME=1, SCE=0). Tekrar
	 * ATANMAYAcak!
	 */

	/* Debug registers */
	vmcb->save.dr6 = 0xFFFF0FF0;
	vmcb->save.dr7 = 0x00000400;

	/* Execution state */
	vmcb->save.rip = g_rip;
	vmcb->save.rsp = g_rsp;
	vmcb->save.rax = 0;
	vmcb->save.rflags = rflags & ~X86_EFLAGS_IF;

	return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Module Init — SVM Setup + Test VMRUN + Procfs
 * ═══════════════════════════════════════════════════════════════════════════
 */

static int __init svm_module_init(void)
{
	u64 efer_val;
	int ret;
	u32 eax, ebx, ecx, edx;

	/* Phase 3.3 Patch: Pin initialization to CPU 0 to prevent MSR fragmentation
	 * (#UD invalid opcode on CLGI)
	 */
	if (set_cpus_allowed_ptr(current, cpumask_of(0))) {
		pr_err("[INIT] Cannot pin to CPU 0 — is it offline?\n");
		return -ENODEV;
	}

	pr_info("=== SVM Modülü Başlatılıyor ===\n");

	/* 0) KVM (Hypervisor) Varlık Testi */
	cpuid(1, &eax, &ebx, &ecx, &edx);
	if (ecx & (1 << 31)) {
		pr_err("KRITIK HATA: KVM / Sanal Makine Tespit Edildi (CPUID.1:ECX.31 = 1). Modül sadece Bare-Metal'de çalıştırılabilir. Yükleme iptal edildi!\n");
		return -EBUSY;
	}

	/* 1) SVM desteği kontrol */
	if (!svm_supported()) {
		pr_err("SVM bu CPU'da desteklenmiyor.\n");
		return -ENODEV;
	}
	pr_info("SVM desteği mevcut.\n");

	mutex_init(&snap_ctx.lock);

	/* 1.5) NPT Init */
	ret = npt_build_identity_map(&svm_ctx.npt, 1ULL << 36); /* 64GB */
	if (ret) {
		pr_err("NPT identity map kurulamadi.\n");
		return ret;
	}

	/* 2) Gizli semboller */
	ret = resolve_hidden_symbols();
	if (ret < 0)
		goto err_npt;

	/* 3) EFER.SVME etkinleştir */
	rdmsrl(MSR_EFER, efer_val);
	if (!(efer_val & EFER_SVME)) {
		efer_val |= EFER_SVME;
		wrmsrl(MSR_EFER, efer_val);
		pr_info("SVME biti etkinleştirildi.\n");
	}

	/* 4) HSAVE alanı */
	svm_ctx.hsave_va = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!svm_ctx.hsave_va) {
		pr_err("HSAVE tahsis hatası.\n");
		ret = -ENOMEM;
		goto err_npt;
	}
	svm_ctx.hsave_pa = virt_to_phys(svm_ctx.hsave_va);
	wrmsrl(MSR_VM_HSAVE_PA, svm_ctx.hsave_pa);

	/* 5) VMCB */
	svm_ctx.vmcb = (struct vmcb *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!svm_ctx.vmcb) {
		ret = -ENOMEM;
		goto err_hsave;
	}
	svm_ctx.vmcb_pa = virt_to_phys(svm_ctx.vmcb);

	/* 6) MSRPM - 64KB (Zen 4 requires 40KB) */
	svm_ctx.msrpm_va = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 4);
	if (!svm_ctx.msrpm_va) {
		ret = -ENOMEM;
		goto err_vmcb;
	}
	svm_ctx.msrpm_pa = virt_to_phys(svm_ctx.msrpm_va);

	/* 7) IOPM - 12KB */
	svm_ctx.iopm_va = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 2);
	if (!svm_ctx.iopm_va) {
		ret = -ENOMEM;
		goto err_msrpm;
	}
	svm_ctx.iopm_pa = virt_to_phys(svm_ctx.iopm_va);

	/* Note: VMCB preparation will now happen dynamically during ioctl
	 * inside the context of the user-space process. We do not set up
	 * dummy guest static fields here anymore.
	 */
	/* ── Proc entries & Trace Init (MUST BE BEFORE VMRUN) ── */
	ret = procfs_init(&snap_ctx);
	if (ret)
		goto err_iopm;

	ret = svm_trace_init();
	if (ret) {
		procfs_exit(&snap_ctx);
		goto err_iopm;
	}

	ret = svm_chardev_init();
	if (ret) {
		svm_trace_cleanup();
		procfs_exit(&snap_ctx);
		goto err_iopm;
	}

	ret = svm_ghost_init();
	if (ret) {
		svm_chardev_exit();
		svm_trace_cleanup();
		procfs_exit(&snap_ctx);
		goto err_iopm;
	}

	pr_info(">>> BAŞARILI! Modül arka planda sessizce /dev/ntp_sync üzerinden hedef bekliyor <<<\n");
	return 0;

err_iopm:
	if (svm_ctx.iopm_va) {
		free_pages((unsigned long)svm_ctx.iopm_va, 2);
		svm_ctx.iopm_va = NULL;
	}
err_msrpm:
	if (svm_ctx.msrpm_va) {
		free_pages((unsigned long)svm_ctx.msrpm_va, 4);
		svm_ctx.msrpm_va = NULL;
	}
err_vmcb:
	if (svm_ctx.vmcb) {
		free_page((unsigned long)svm_ctx.vmcb);
		svm_ctx.vmcb = NULL;
	}
err_hsave:
	if (svm_ctx.hsave_va) {
		free_page((unsigned long)svm_ctx.hsave_va);
		svm_ctx.hsave_va = NULL;
	}
err_npt:
	npt_destroy(&svm_ctx.npt);
	return ret;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Module Exit
 * ═══════════════════════════════════════════════════════════════════════════
 */

static void __exit svm_module_exit(void)
{
	u64 efer_val;

	/*
	 * Clean-up MUST run on CPU 0 to wipe the correct MSR_VM_HSAVE_PA.
	 * If rmmod runs on CPU 2, CPU 0's MSR is left permanently poisoned.
	 */
	set_cpus_allowed_ptr(current, cpumask_of(0));

	/*
	 * Paranoid: refuse to disable SVM if a guest is still running.
	 * Module refcount should prevent this, but defense-in-depth.
	 */
	if (atomic_read(&matrix_active) != 0) {
		pr_crit("[EXIT] WARNING: matrix_active != 0 during module unload!\n");
		atomic_set(&matrix_active, 0);
	}

	/* Phase 3.1: No kthread cleanup anymore */

	svm_ghost_exit();
	svm_chardev_exit();
	svm_trace_cleanup();

	/* Procfs + watcher cleanup */
	procfs_exit(&snap_ctx);
	npt_destroy(&svm_ctx.npt);

	/* SVM cleanup */
	rdmsrl(MSR_EFER, efer_val);
	efer_val &= ~EFER_SVME;
	wrmsrl(MSR_EFER, efer_val);

	/* Phase 3.1: No dummy code payload cleanup anymore */
	if (svm_ctx.iopm_va) {
		free_pages((unsigned long)svm_ctx.iopm_va, 2);
		svm_ctx.iopm_va = NULL;
	}
	if (svm_ctx.msrpm_va) {
		free_pages((unsigned long)svm_ctx.msrpm_va, 4);
		svm_ctx.msrpm_va = NULL;
	}
	if (svm_ctx.vmcb) {
		free_page((unsigned long)svm_ctx.vmcb);
		svm_ctx.vmcb = NULL;
	}
	if (svm_ctx.hsave_va) {
		free_page((unsigned long)svm_ctx.hsave_va);
		svm_ctx.hsave_va = NULL;
	}

	pr_info("SVM modülü temizlendi.\n");
}

module_init(svm_module_init);
module_exit(svm_module_exit);
