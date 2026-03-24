/*
 * main.c — Module Init/Exit + VMCB Prepare (V4.0 Stealth)
 *
 * Module lifecycle: SVM hardware init, test VMRUN, proc entries.
 * vmcb_prepare_npt: Full VMCB configuration with V4.0 stealth intercepts.
 */

#include "ring_minus_one.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hakan");
MODULE_DESCRIPTION("AMD-V SVM Ring -1 Unified Engine V4.0");
MODULE_IMPORT_NS("KVM_AMD");

/* ═══════════════════════════════════════════════════════════════════════════
 *  Singleton Contexts (Local to main.c, passed explicitly to others or via ptr)
 * ═══════════════════════════════════════════════════════════════════════════ */

static struct svm_context svm_ctx = {0};
static struct snap_context snap_ctx = {0};

struct svm_context *g_svm = &svm_ctx;
struct snap_context *g_snap = &snap_ctx;

/* ═══════════════════════════════════════════════════════════════════════════
 *  VMCB Prepare — V4.0 Stealth Intercepts
 * ═══════════════════════════════════════════════════════════════════════════ */

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
    asm volatile("str  %0"      : "=r"(tr));
    asm volatile("sgdt %0"      : "=m"(gdtr));
    asm volatile("sidt %0"      : "=m"(idtr));
    rdmsrl(MSR_FS_BASE, fs_base);
    rdmsrl(MSR_GS_BASE, gs_base);

    /* ── Intercepts ── */

    /* VMRUN (mandatory) */
    vmcb->control.intercepts[INTERCEPT_VMRUN >> 5] |=
        (1U << (INTERCEPT_VMRUN & 31));
    /* HLT */
    vmcb->control.intercepts[INTERCEPT_HLT >> 5] |=
        (1U << (INTERCEPT_HLT & 31));
    /* CPUID — uniform latency, prevent timing fingerprint */
    vmcb->control.intercepts[INTERCEPT_CPUID >> 5] |=
        (1U << (INTERCEPT_CPUID & 31));
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
        /* MSR 0xC0000081 (STAR): rdmsr + wrmsr */
        msrpm[0x800 + (0x81 * 2) / 8] |= (3 << ((0x81 * 2) % 8));
        /* MSR 0xC0000082 (LSTAR): rdmsr + wrmsr */
        msrpm[0x800 + (0x82 * 2) / 8] |= (3 << ((0x82 * 2) % 8));
        /* MSR 0xC0000103 (TSC_AUX): rdmsr */
        msrpm[0x800 + (0x103 * 2) / 8] |= (1 << ((0x103 * 2) % 8));

        /* MSR 0xC0010015 (K8_HWCR): rdmsr — SVME_LOCK spoofing */
        msrpm[0x1000 + (0x15 * 2) / 8] |= (1 << ((0x15 * 2) % 8));

        /* MSR 0xC0010114 (SVM_LOCK_KEY): rdmsr — SVM presence hiding */
        msrpm[0x1000 + (0x114 * 2) / 8] |= (1 << ((0x114 * 2) % 8));

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
    vmcb->control.iopm_base_pa  = ctx->iopm_pa;

    /* ASID-only isolation, no TLB flush penalty */
    vmcb->control.asid = 2;
    vmcb->control.tlb_ctl = 0;
    
    vmcb->control.virt_ext |= LBR_CTL_ENABLE_MASK; // LBR Bleed Koruması!
    
    /* First VMRUN: clean=0 forces full load. Subsequent runs use STABLE. */
    vmcb->control.clean = 0;

    /* NPT configuration */
    if (npt && npt->pml4_pa) {
        vmcb->control.nested_ctl = 1;
        vmcb->control.nested_cr3 = npt->pml4_pa;
        pr_info("[VMCB] NPT enabled, nested_cr3=0x%llx\n",
                (u64)npt->pml4_pa);
    }

    /* TSC offset — per-CPU */
    vmcb->control.tsc_offset = *this_cpu_ptr(&pcpu_tsc_offset);

    /* ── Segment Registers ── */
    vmcb->save.cs.selector = cs;
    vmcb->save.cs.attrib   = 0x029B;
    vmcb->save.cs.limit    = 0xFFFFFFFF;
    vmcb->save.cs.base     = 0;

    vmcb->save.ds.selector = ds;
    vmcb->save.ds.attrib   = 0x0093;
    vmcb->save.ds.limit    = 0xFFFFFFFF;
    vmcb->save.ds.base     = 0;

    vmcb->save.es.selector = es;
    vmcb->save.es.attrib   = 0x0093;
    vmcb->save.es.limit    = 0xFFFFFFFF;
    vmcb->save.es.base     = 0;

    vmcb->save.ss.selector = ss;
    vmcb->save.ss.attrib   = 0x0093;
    vmcb->save.ss.limit    = 0xFFFFFFFF;
    vmcb->save.ss.base     = 0;

    vmcb->save.fs.selector = fs;
    vmcb->save.fs.attrib   = 0x0093;
    vmcb->save.fs.limit    = 0xFFFFFFFF;
    vmcb->save.fs.base     = fs_base;

    vmcb->save.gs.selector = gs;
    vmcb->save.gs.attrib   = 0x0093;
    vmcb->save.gs.limit    = 0xFFFFFFFF;
    vmcb->save.gs.base     = gs_base;

    vmcb->save.gdtr.limit = gdtr.size;
    vmcb->save.gdtr.base  = gdtr.address;
    vmcb->save.idtr.limit = idtr.size;
    vmcb->save.idtr.base  = idtr.address;

    vmcb->save.tr.selector = tr;
    vmcb->save.tr.limit    = 0xFFFF;
    vmcb->save.tr.base     = 0;
    vmcb->save.tr.attrib   = 0x008B;

    /* Control registers */
    vmcb->save.cr0  = cr0;
    vmcb->save.cr3  = g_cr3 ? g_cr3 : (cr3 & 0xFFFFFFFFFFFFF000ULL);
    vmcb->save.cr4  = cr4;
    vmcb->save.efer = efer_val;

    /* Debug registers */
    vmcb->save.dr6 = 0xFFFF0FF0;
    vmcb->save.dr7 = 0x00000400;

    /* Execution state */
    vmcb->save.rip    = g_rip;
    vmcb->save.rsp    = g_rsp;
    vmcb->save.rax    = 0;
    vmcb->save.rflags = rflags & ~X86_EFLAGS_IF;

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Module Init — SVM Setup + Test VMRUN + Procfs
 * ═══════════════════════════════════════════════════════════════════════════ */

static int __init svm_module_init(void)
{
    u64 efer_val, cr0, cr4, rflags;
    unsigned long cr3;
    u16 cs, ds, ss, es, fs, gs, tr;
    struct desc_ptr gdtr, idtr;
    u64 fs_base, gs_base;
    u64 guest_rsp;
    int ret;

    pr_info("=== SVM Modülü Başlatılıyor ===\n");

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

    /* 6) MSRPM - 8KB */
    svm_ctx.msrpm_va = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
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

    /* 8) Guest kod ve stack */
    svm_ctx.code_page  = (u8 *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    svm_ctx.stack_page = (u8 *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    if (!svm_ctx.code_page || !svm_ctx.stack_page) {
        ret = -ENOMEM;
        goto err_guest;
    }

    ret = my_set_memory_x((unsigned long)svm_ctx.code_page, 1);
    if (ret)
        goto err_guest;

    memcpy(svm_ctx.code_page, guest_code_bin, 3);
    guest_rsp = (u64)svm_ctx.stack_page + PAGE_SIZE - 16;

    /* 9) Host state */
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
    asm volatile("str  %0"      : "=r"(tr));
    asm volatile("sgdt %0"      : "=m"(gdtr));
    asm volatile("sidt %0"      : "=m"(idtr));
    rdmsrl(MSR_FS_BASE, fs_base);
    rdmsrl(MSR_GS_BASE, gs_base);

    /* ── VMCB Init — Use context-based prepare ── */
    vmcb_prepare_npt(&svm_ctx, (u64)svm_ctx.code_page, guest_rsp, cr3 & 0xFFFFFFFFFFFFF000ULL);


    pr_info("=== Konuk başlatılıyor (VMEXIT dispatch loop) ===\n");

    /* ── VMRUN Dispatch Loop — handles CPUID/MSR/IOIO/HLT ── */
    ret = svm_run_guest(&svm_ctx);

    raw_cr3_flush();

    if (ret) {
        pr_err(">>> Guest döngüsü hata ile çıktı: %d <<<\n", ret);
        goto err_guest;
    }

    pr_info(">>> BAŞARILI! Guest normal çıkış yaptı <<<\n");

    /* ── Proc entries ── */
    ret = procfs_init(&snap_ctx);
    if (ret)
        goto err_guest;

    return 0;

err_guest:
    if (svm_ctx.code_page) {
        if (my_set_memory_nx)
            my_set_memory_nx((unsigned long)svm_ctx.code_page, 1);
        free_page((unsigned long)svm_ctx.code_page);
    }
    if (svm_ctx.stack_page)
        free_page((unsigned long)svm_ctx.stack_page);
    if (svm_ctx.iopm_va)
        free_pages((unsigned long)svm_ctx.iopm_va, 2);
err_msrpm:
    if (svm_ctx.msrpm_va)
        free_pages((unsigned long)svm_ctx.msrpm_va, 1);
err_vmcb:
    if (svm_ctx.vmcb)
        free_page((unsigned long)svm_ctx.vmcb);
err_hsave:
    if (svm_ctx.hsave_va)
        free_page((unsigned long)svm_ctx.hsave_va);
err_npt:
    npt_destroy(&svm_ctx.npt);
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Module Exit
 * ═══════════════════════════════════════════════════════════════════════════ */

static void __exit svm_module_exit(void)
{
    u64 efer_val;

    /* Procfs + watcher cleanup */
    procfs_exit(&snap_ctx);
    npt_destroy(&svm_ctx.npt);

    /* SVM cleanup */
    rdmsrl(MSR_EFER, efer_val);
    efer_val &= ~EFER_SVME;
    wrmsrl(MSR_EFER, efer_val);

    if (svm_ctx.code_page) {
        if (my_set_memory_nx)
            my_set_memory_nx((unsigned long)svm_ctx.code_page, 1);
        free_page((unsigned long)svm_ctx.code_page);
    }
    if (svm_ctx.stack_page)
        free_page((unsigned long)svm_ctx.stack_page);
    if (svm_ctx.iopm_va)
        free_pages((unsigned long)svm_ctx.iopm_va, 2);
    if (svm_ctx.msrpm_va)
        free_pages((unsigned long)svm_ctx.msrpm_va, 1);
    if (svm_ctx.vmcb)
        free_page((unsigned long)svm_ctx.vmcb);
    if (svm_ctx.hsave_va)
        free_page((unsigned long)svm_ctx.hsave_va);

    pr_info("SVM modülü temizlendi.\n");
}

module_init(svm_module_init);
module_exit(svm_module_exit);
