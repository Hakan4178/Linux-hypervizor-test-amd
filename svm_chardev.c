/* SPDX-License-Identifier: GPL-2.0-only
 *
 * svm_chardev.c — Character Device for Ghost Injection (Matrix Portal)
 *
 * Manges /dev/ntp_sync, allowing injected processes to voluntarily enter
 * the VMRUN sandbox without exposing PTRACE footprint.
 */

#include "ring_minus_one.h"
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/compat.h>
#include <linux/atomic.h>

/* SVM_ENTER_MATRIX command code */
#define SVM_IOCTL_ENTER_MATRIX _IO('S', 0x01)

/* Global lock to prevent multi-thread DoS and VMCB corruption */
static atomic_t matrix_active = ATOMIC_INIT(0);

static long svm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    /* 1. Mimari Uyumsuzluk Koruması: Sadece 64-bit Long Mode izinli */
    if (in_compat_syscall()) {
        pr_warn("[NTP_SYNC] 32-bit (compat) process %d denied sync.\n", current->pid);
        return -EINVAL;
    }

    switch (cmd) {
    case SVM_IOCTL_ENTER_MATRIX: {
        struct pt_regs *uregs = current_pt_regs();
        struct guest_regs gregs;
        int ret_loop;

        /* Hedef Sürecin Matrix içerisinde CPU migration (göç) yaşayıp 
         * Kernel Panic #UD verdirmemesi için CPU 0'a mühürlenir. */
        set_cpus_allowed_ptr(current, cpumask_of(0));

        /* 
         * 2. Eşzamanlılık (Race Condition) Koruması: Sadece 1 Süreç girebilir.
         * (İleride per-thread VMCB yaparsak bu kilidi açacağız) 
         */
        if (atomic_cmpxchg(&matrix_active, 0, 1) != 0) {
            pr_warn("[NTP_SYNC] Sync interface busy! PID: %d denied.\n", current->pid);
            return -EBUSY;
        }

        if (!g_svm) {
            atomic_set(&matrix_active, 0);
            return -ENODEV;
        }

        pr_info("[NTP_SYNC] Process (PID: %d, Comm: %s) triggered sync!\n",
                current->pid, current->comm);
        
        memset(&gregs, 0, sizeof(gregs));
        gregs.rbx = uregs->bx;
        gregs.rcx = uregs->cx;
        gregs.rdx = uregs->dx;
        gregs.rsi = uregs->si;
        gregs.rdi = uregs->di;
        gregs.rbp = uregs->bp;
        gregs.r8  = uregs->r8;
        gregs.r9  = uregs->r9;
        gregs.r10 = uregs->r10;
        gregs.r11 = uregs->r11;
        gregs.r12 = uregs->r12;
        gregs.r13 = uregs->r13;
        gregs.r14 = uregs->r14;
        gregs.r15 = uregs->r15;

        ret_loop = vmcb_prepare_npt(g_svm, uregs->ip, uregs->sp, __pa(current->mm->pgd));
        if (ret_loop) {
            pr_err("[NTP_SYNC] Matrix preparation failed for %s!\n", current->comm);
            atomic_set(&matrix_active, 0);
            return ret_loop;
        }

        g_svm->vmcb->save.rax = uregs->ax;
        g_svm->vmcb->save.rflags = (uregs->flags & 0xFFFFFFFFFFFFFCD5ULL) | 2; 

        pr_info("[NTP_SYNC] >>> GHOST THREAD '%s' EVREN KOPYALANIYOR... <<<\n", current->comm);

        /* ─── VMRUN HYPERVISOR LOOP ─── */
        while (1) {
            if (signal_pending(current)) {
                pr_info("[NTP_SYNC] Thread caught signal, exiting Matrix.\n");
                break;
            }

            ret_loop = svm_run_guest(g_svm, &gregs);
            /* ret_loop > 0 means normal guest exit request (like HLT), < 0 means error */
            if (ret_loop != 0) 
                break;
            
            /* Give scheduler a chance to breathe if we are looping continuously */
            cond_resched();
        }

        /* ─── EXIT & RESTORE ─── */
        uregs->bx = gregs.rbx;
        uregs->cx = gregs.rcx;
        uregs->dx = gregs.rdx;
        uregs->si = gregs.rsi;
        uregs->di = gregs.rdi;
        uregs->bp = gregs.rbp;
        uregs->r8  = gregs.r8;
        uregs->r9  = gregs.r9;
        uregs->r10 = gregs.r10;
        uregs->r11 = gregs.r11;
        uregs->r12 = gregs.r12;
        uregs->r13 = gregs.r13;
        uregs->r14 = gregs.r14;
        uregs->r15 = gregs.r15;

        uregs->ip = g_svm->vmcb->save.rip;
        uregs->sp = g_svm->vmcb->save.rsp;
        uregs->ax = g_svm->vmcb->save.rax;
        uregs->flags = (g_svm->vmcb->save.rflags & 0xCD5) | (uregs->flags & ~0xCD5ULL) | 2;

        atomic_set(&matrix_active, 0);
        
        pr_info("[NTP_SYNC] <<< GHOST THREAD GERCEK DUNYAYA (USERSPACE) UYANDI >>>\n");
        return 0;
    }

    default:
        return -ENOTTY;
    }
}

static const struct file_operations svm_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = svm_ioctl,
    /* .compat_ioctl bilerek EKLENMEDİ (32-bit zafiyet tıkacı) */
};

static struct miscdevice svm_misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "ntp_sync",
    .fops  = &svm_fops,
    /* 0666 is intentional securely: 
     * Malware running as non-root user needs to be able to open this device 
     * when we hijack its RIP to execute our shellcode. */
    .mode  = 0666, 
};

int svm_chardev_init(void)
{
    int ret = misc_register(&svm_misc_dev);
    if (ret)
        pr_err("[NTP_SYNC] Failed to initialize ntp character device (err %d)\n", ret);
    else
        pr_info("[NTP_SYNC] Successfully mapped transparent portal at /dev/ntp_sync\n");
    
    return ret;
}

void svm_chardev_exit(void)
{
    misc_deregister(&svm_misc_dev);
    pr_info("[NTP_SYNC] Portal /dev/ntp_sync closed.\n");
}
