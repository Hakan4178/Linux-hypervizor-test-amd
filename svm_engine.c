/*
 * svm_engine.c — SVM Hardware Primitives
 *
 * Global değişken tanımları, SVM destegi kontrolü,
 * gizli sembol çözümleme, ve VMRUN wrapper.
 */

#include "ring_minus_one.h"
#include <linux/mutex.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  Global Değişken Tanımları (Yardımcı Fonksiyonlar için)
 * ═══════════════════════════════════════════════════════════════════════════ */

set_memory_x_t  my_set_memory_x = NULL;
set_memory_nx_t my_set_memory_nx = NULL;
static DEFINE_MUTEX(kprobe_mutex);

/* ═══════════════════════════════════════════════════════════════════════════
 *  SVM Donanım Kontrolleri
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * svm_supported - CPUID ile SVM desteğini kontrol et
 */
bool svm_supported(void)
{
    u32 eax, ebx, ecx, edx;

    cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
    return !!(ecx & (1 << 2));
}

/*
 * resolve_hidden_symbols - kprobes ile set_memory_x/nx adreslerini çöz
 */
int resolve_hidden_symbols(void)
{
    struct kprobe kp_x  = { .symbol_name = "set_memory_x" };
    struct kprobe kp_nx = { .symbol_name = "set_memory_nx" };
    int ret = 0;

    mutex_lock(&kprobe_mutex);

    if (register_kprobe(&kp_x) < 0) {
        pr_err("set_memory_x adresi bulunamadı!\n");
        ret = -EFAULT;
        goto out;
    }
    my_set_memory_x = (set_memory_x_t)kp_x.addr;
    unregister_kprobe(&kp_x);

    if (register_kprobe(&kp_nx) < 0) {
        pr_err("set_memory_nx adresi bulunamadı!\n");
        ret = -EFAULT;
        goto out;
    }
    my_set_memory_nx = (set_memory_nx_t)kp_nx.addr;
    unregister_kprobe(&kp_nx);

    pr_info("Semboller çözümlendi: set_memory_x=%pK, set_memory_nx=%pK\n",
            my_set_memory_x, my_set_memory_nx);

out:
    mutex_unlock(&kprobe_mutex);
    return ret;
}

/*
 * vmrun_safe - VMRUN with full GPR preservation + CLGI/STGI
 */
void vmrun_safe(u64 vmcb_pa)
{
    asm volatile (
        "push %%rbx  \n\t"
        "push %%rcx  \n\t"
        "push %%rdx  \n\t"
        "push %%rsi  \n\t"
        "push %%rdi  \n\t"
        "push %%rbp  \n\t"
        "push %%r8   \n\t"
        "push %%r9   \n\t"
        "push %%r10  \n\t"
        "push %%r11  \n\t"
        "push %%r12  \n\t"
        "push %%r13  \n\t"
        "push %%r14  \n\t"
        "push %%r15  \n\t"
        "clgi        \n\t"
        "vmrun %%rax \n\t"
        "stgi        \n\t"
        "pop %%r15   \n\t"
        "pop %%r14   \n\t"
        "pop %%r13   \n\t"
        "pop %%r12   \n\t"
        "pop %%r11   \n\t"
        "pop %%r10   \n\t"
        "pop %%r9    \n\t"
        "pop %%r8    \n\t"
        "pop %%rbp   \n\t"
        "pop %%rdi   \n\t"
        "pop %%rsi   \n\t"
        "pop %%rdx   \n\t"
        "pop %%rcx   \n\t"
        "pop %%rbx   \n\t"
        :
        : "a"(vmcb_pa)
        : "memory", "cc"
    );
}

/*
 * vmrun_with_regs - VMRUN with full guest GPR save/restore
 * @vmcb_pa: Physical address of VMCB (loaded into RAX for VMRUN)
 * @regs: Guest GPR state (software-managed, NOT saved by hardware)
 *
 * On VMRUN, hardware loads RAX/RSP/RIP/RFLAGS from VMCB save area.
 * All other GPRs must be loaded from @regs before VMRUN and saved
 * back to @regs after VMEXIT. This enables VMEXIT handlers to
 * inspect/modify guest register state (e.g. CPUID results).
 *
 * Stack protocol:
 *   1. Push host callee-saved regs
 *   2. Push @regs pointer
 *   3. Load guest GPRs from @regs (RSI last, since it holds the pointer)
 *   4. CLGI + VMRUN + STGI
 *   5. XCHG RSI with saved pointer on stack
 *   6. Save guest GPRs to @regs
 *   7. Pop host callee-saved regs
 */
void vmrun_with_regs(u64 vmcb_pa, struct guest_regs *regs)
{
    if (unlikely(!regs)) {
        pr_err("[SVM] vmrun_with_regs NULL regs pointer koruması tetiklendi!\n");
        return;
    }

    asm volatile (
        /* === Save host callee-saved registers === */
        "push %%rbx   \n\t"
        "push %%r12   \n\t"
        "push %%r13   \n\t"
        "push %%r14   \n\t"
        "push %%r15   \n\t"
        "push %%rbp   \n\t"

        /* === Save regs pointer on stack === */
        "push %%rsi   \n\t"

        /* === Load guest GPRs from struct (RSI = regs pointer) === */
        "mov  0x00(%%rsi), %%rbx \n\t"   /* regs->rbx */
        "mov  0x08(%%rsi), %%rcx \n\t"   /* regs->rcx */
        "mov  0x10(%%rsi), %%rdx \n\t"   /* regs->rdx */
        /* skip rsi (0x18) — load LAST */
        "mov  0x20(%%rsi), %%rdi \n\t"   /* regs->rdi */
        "mov  0x28(%%rsi), %%rbp \n\t"   /* regs->rbp */
        "mov  0x30(%%rsi), %%r8  \n\t"   /* regs->r8  */
        "mov  0x38(%%rsi), %%r9  \n\t"   /* regs->r9  */
        "mov  0x40(%%rsi), %%r10 \n\t"   /* regs->r10 */
        "mov  0x48(%%rsi), %%r11 \n\t"   /* regs->r11 */
        "mov  0x50(%%rsi), %%r12 \n\t"   /* regs->r12 */
        "mov  0x58(%%rsi), %%r13 \n\t"   /* regs->r13 */
        "mov  0x60(%%rsi), %%r14 \n\t"   /* regs->r14 */
        "mov  0x68(%%rsi), %%r15 \n\t"   /* regs->r15 */
        "mov  0x18(%%rsi), %%rsi \n\t"   /* regs->rsi — LAST! */

        /* === VMRUN === */
        "clgi         \n\t"
        "vmrun %%rax  \n\t"
        "stgi         \n\t"

        /* === After VMEXIT: all GPRs = guest values === */
        /* Recover regs pointer: swap guest RSI with saved pointer */
        "xchg %%rsi, (%%rsp) \n\t"
        /* Now: RSI = regs pointer, (RSP) = guest RSI */

        /* === Save guest GPRs to struct === */
        "mov  %%rbx, 0x00(%%rsi) \n\t"   /* regs->rbx */
        "mov  %%rcx, 0x08(%%rsi) \n\t"   /* regs->rcx */
        "mov  %%rdx, 0x10(%%rsi) \n\t"   /* regs->rdx */
        /* Save guest RSI from stack */
        "pop  %%rbx              \n\t"   /* rbx = guest RSI */
        "mov  %%rbx, 0x18(%%rsi) \n\t"   /* regs->rsi */
        "mov  %%rdi, 0x20(%%rsi) \n\t"   /* regs->rdi */
        "mov  %%rbp, 0x28(%%rsi) \n\t"   /* regs->rbp */
        "mov  %%r8,  0x30(%%rsi) \n\t"   /* regs->r8  */
        "mov  %%r9,  0x38(%%rsi) \n\t"   /* regs->r9  */
        "mov  %%r10, 0x40(%%rsi) \n\t"   /* regs->r10 */
        "mov  %%r11, 0x48(%%rsi) \n\t"   /* regs->r11 */
        "mov  %%r12, 0x50(%%rsi) \n\t"   /* regs->r12 */
        "mov  %%r13, 0x58(%%rsi) \n\t"   /* regs->r13 */
        "mov  %%r14, 0x60(%%rsi) \n\t"   /* regs->r14 */
        "mov  %%r15, 0x68(%%rsi) \n\t"   /* regs->r15 */

        /* === Restore host callee-saved registers === */
        "pop  %%rbp   \n\t"
        "pop  %%r15   \n\t"
        "pop  %%r14   \n\t"
        "pop  %%r13   \n\t"
        "pop  %%r12   \n\t"
        "pop  %%rbx   \n\t"
        :
        : "a"(vmcb_pa), "S"(regs)
        : "memory", "cc", "rcx", "rdx", "rdi",
          "r8", "r9", "r10", "r11"
    );
}

/*
 * raw_cr3_flush - CR3 yeniden yükle (TLB flush)
 */
void raw_cr3_flush(void)
{
    unsigned long cr3;

    /* lfence bariyerleri eklenerek Meltdown/Spectre TLB Side-Channel engellendi */
    asm volatile(
        "lfence \n\t"
        "mov %%cr3, %0 \n\t"
        "mov %0, %%cr3 \n\t"
        "lfence \n\t"
        : "=r"(cr3)
        :: "memory");
}
