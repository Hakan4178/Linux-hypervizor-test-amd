// SPDX-License-Identifier: GPL-2.0-only
/*
 * Character Device for Ghost Injection (Matrix Portal)
 *
 * Manges /dev/ntp_sync, allowing injected processes to voluntarily enter
 * the VMRUN sandbox without exposing PTRACE footprint.
 */

#include "ring_minus_one.h"
#include "npt_walk.h"
#include <linux/atomic.h>
#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/wait.h>

extern wait_queue_head_t svm_trace_wq;

/* SVM_ENTER_MATRIX command code */
#define SVM_IOCTL_ENTER_MATRIX _IO('S', 0x01)

/* Global lock to prevent multi-thread DoS and VMCB corruption */
atomic_t matrix_active = ATOMIC_INIT(0);
static pid_t matrix_owner_pid;

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
		struct matrix_exit_info k_exit_info;
		struct matrix_exit_info __user *u_exit_info = (struct matrix_exit_info __user *)arg;
		int has_u_exit_info = 0;
		int is_resume = 0;
		int ret_loop = 0;

		memset(&k_exit_info, 0, sizeof(k_exit_info));

		if (arg) {
			if (copy_from_user(&k_exit_info, u_exit_info, sizeof(k_exit_info)))
				return -EFAULT;
			has_u_exit_info = 1;
		}

		/*
		 * Hedef Sürecin Matrix içerisinde CPU migration (göç) yaşayıp
		 * Kernel Panic #UD verdirmemesi için CPU 0'a mühürlenir.
		 * Resume durumunda zaten pinli olmalı, tekrar çağırmak VMCB
		 * TLB/ASID state'ini bozabilir.
		 */

		/* Eğer u_exit_info varsa ve reason SYSCALL ise, bu bir RESUME
		 * describesidir! ioctl loop'u baştan initialize EDGE'den atla!
		 */
		is_resume =
		    (has_u_exit_info && k_exit_info.exit_reason == MATRIX_EXIT_REASON_SYSCALL);

		if (!is_resume) {
			/*
			 * 2. Eşzamanlılık (Race Condition) Koruması: Sadece 1 Süreç girebilir.
			 */
			if (atomic_cmpxchg(&matrix_active, 0, 1) != 0) {
				pr_warn("[NTP_SYNC] Sync interface busy! PID: %d denied.\n",
					current->pid);
				return -EBUSY;
			}

			/* Pin to CPU 0 only on initial entry */
			if (set_cpus_allowed_ptr(current, cpumask_of(0))) {
				pr_err("[NTP_SYNC] Affinity failed! Cannot lock to CPU 0.\n");
				atomic_set(&matrix_active, 0);
				return -EINVAL;
			}

			if (!g_svm) {
				atomic_set(&matrix_active, 0);
				return -ENODEV;
			}

			pr_info("[NTP_SYNC] Process (PID: %d, Comm: %s) triggered sync!\n",
				current->pid, current->comm);

			/* Track which process owns the matrix session */
			matrix_owner_pid = current->pid;

			memset(&g_svm->gregs, 0, sizeof(g_svm->gregs));
			g_svm->gregs.rbx = uregs->bx;
			g_svm->gregs.rcx = uregs->cx;
			g_svm->gregs.rdx = uregs->dx;
			g_svm->gregs.rsi = uregs->si;
			g_svm->gregs.rdi = uregs->di;
			g_svm->gregs.rbp = uregs->bp;
			g_svm->gregs.r8 = uregs->r8;
			g_svm->gregs.r9 = uregs->r9;
			g_svm->gregs.r10 = uregs->r10;
			g_svm->gregs.r11 = uregs->r11;
			g_svm->gregs.r12 = uregs->r12;
			g_svm->gregs.r13 = uregs->r13;
			g_svm->gregs.r14 = uregs->r14;
			g_svm->gregs.r15 = uregs->r15;

			ret_loop =
			    vmcb_prepare_npt(g_svm, uregs->ip, uregs->sp, __pa(current->mm->pgd));
			if (ret_loop) {
				pr_err("[NTP_SYNC] Matrix preparation failed for %s!\n",
				       current->comm);
				atomic_set(&matrix_active, 0);
				return ret_loop;
			}

			/* 
			 * KICKSTART: Mark the initial guest stack page as Read-Only.
			 * This ensures a 'Dirty Page' event is generated immediately on the 
			 * first stack write, verifying the NPT telemetry pipeline is alive.
			 */
			npt_set_page_ro(&g_svm->npt, uregs->sp & PAGE_MASK);

			/* Mimarinin Cekirdegi: Kuantum Ayrilmasi (Fork-like behavior)
			 * Gercek dunyada (Host) ioctl 0 dondururken,
			 * Matrix evrenindeki process 1 dondurdugunu gorecek!
			 * Boyece Host = Trampoline/Proxy moduna girerken,
			 * Guest = Direk Target Payload'a siçrayacak!
			 */
			g_svm->vmcb->save.rax = 1;

			g_svm->vmcb->save.rflags = (uregs->flags & 0xFFFFFFFFFFFFFCD5ULL) | 2;

			pr_info("[NTP_SYNC] >>> GHOST THREAD '%s' EVREN KOPYALANIYOR... <<<\n",
				current->comm);
		} else {
			/*
			 * RESUMING from a Userspace Syscall!
			 * Validate matrix_active to prevent race with uninitialized g_svm.
			 */
			if (atomic_read(&matrix_active) != 1 ||
			    matrix_owner_pid != current->pid) {
				pr_warn("[NTP_SYNC] Resume denied: not owner! PID: %d (owner: %d)\n",
					current->pid, matrix_owner_pid);
				return -EINVAL;
			}
			g_svm->vmcb->save.rax = k_exit_info.rax;
			k_exit_info.exit_reason = MATRIX_EXIT_REASON_NONE;
		}

		/* ─── VMRUN HYPERVISOR LOOP ─── */
		while (1) {
			if (signal_pending(current)) {
				pr_info("[NTP_SYNC] Thread caught signal, exiting Matrix.\n");
				ret_loop = -EINTR;
				break;
			}

			ret_loop = svm_run_guest(g_svm, &g_svm->gregs);

			/* ret_loop > 0 means normal guest exit request (like HLT or Syscall
			 * Target), < 0 means error
			 */
			if (ret_loop != 0)
				break;

			/* Give scheduler a chance to breathe if we are looping continuously */
			cond_resched();
		}

		/* ─── EXIT & RESTORE ─── */
		/* ─── EXIT & RESTORE ─── */
		/* If ret_loop == 2, it's a SYSCALL Passthrough Request from vmexit.c! */
		if (ret_loop == 2 && has_u_exit_info) {
			k_exit_info.exit_reason = MATRIX_EXIT_REASON_SYSCALL;
			k_exit_info.rax = g_svm->vmcb->save.rax;
			k_exit_info.rdi = g_svm->gregs.rdi;
			k_exit_info.rsi = g_svm->gregs.rsi;
			k_exit_info.rdx = g_svm->gregs.rdx;
			k_exit_info.r10 = g_svm->gregs.r10;
			k_exit_info.r8 = g_svm->gregs.r8;
			k_exit_info.r9 = g_svm->gregs.r9;
		}

		// Just copy out the entire current guest state so the Trampoline can use
		// it!
		if (has_u_exit_info) {
			/*
			 * FIX 9: Info Leak / KASLR Bypass Korumasi.
			 * Sadece kullanici alani (User-Space) adreslerini disari sizdir.
			 */
			if (g_svm->vmcb->save.rip < TASK_SIZE_MAX)
				k_exit_info.guest_rip = g_svm->vmcb->save.rip;
			else
				k_exit_info.guest_rip = 0; // Kernel adresini gizle

			/* vmexit.c will set k_exit_info.exit_reason = 1 during #UD proxy */
			if (copy_to_user(u_exit_info, &k_exit_info, sizeof(k_exit_info))) {
				atomic_set(&matrix_active, 0);
				wake_up_interruptible(&svm_trace_wq);
				return -EFAULT;
			}

			/* If reason is 1, DO NOT reset matrix_active, DO NOT clear userspace regs
			 * to the target state! The trampoline shellcode needs to continue
			 * normally (returning 0) and MUST keep its OWN userspace registers!
			 */
			if (k_exit_info.exit_reason == MATRIX_EXIT_REASON_SYSCALL)
				return 0; // Return gracefully to the shellcode trampoline!
		}

		/*
		 * FIX 3: Privilege Escalation (LPE) Koruması.
		 * MUST run BEFORE any uregs restoration to prevent speculative
		 * execution of attacker-controlled register values.
		 */
		if (g_svm->vmcb->save.rip >= TASK_SIZE_MAX ||
		    g_svm->vmcb->save.rsp >= TASK_SIZE_MAX) {
			pr_err("[NTP_SYNC] SECURITY: LPE Exploit detected! Terminating Matrix process %d\n",
			       current->pid);
			force_sig(SIGKILL);

			atomic_set(&matrix_active, 0);
			wake_up_interruptible(&svm_trace_wq);
			return -EPERM;
		}

		// REAL EXIT: We are aborting or permanently returning to target
		uregs->bx = g_svm->gregs.rbx;
		uregs->cx = g_svm->gregs.rcx;
		uregs->dx = g_svm->gregs.rdx;
		uregs->si = g_svm->gregs.rsi;
		uregs->di = g_svm->gregs.rdi;
		uregs->bp = g_svm->gregs.rbp;
		uregs->r8 = g_svm->gregs.r8;
		uregs->r9 = g_svm->gregs.r9;
		uregs->r10 = g_svm->gregs.r10;
		uregs->r11 = g_svm->gregs.r11;
		uregs->r12 = g_svm->gregs.r12;
		uregs->r13 = g_svm->gregs.r13;
		uregs->r14 = g_svm->gregs.r14;
		uregs->r15 = g_svm->gregs.r15;

		/*
		 * CRITICAL: If a Trampoline (u_exit_info) is managing the VM, we MUST NOT
		 * clobber the Trampoline's Host `pt_regs`! The Trampoline must wake up
		 * at its native ioctl return address to cleanly call Host sys_exit().
		 * (If this isn't a Trampoline, we are falling back to the target directly).
		 */
		if (!has_u_exit_info) {
			uregs->ip = g_svm->vmcb->save.rip;
			uregs->sp = g_svm->vmcb->save.rsp;
			uregs->ax = g_svm->vmcb->save.rax;
			uregs->flags = (g_svm->vmcb->save.rflags & 0xFFFFFFFFFFFFFCD5ULL) | 2;
		}

		atomic_set(&matrix_active, 0);
		wake_up_interruptible(&svm_trace_wq);

		pr_info("[NTP_SYNC] <<< GHOST THREAD GERCEK DUNYAYA (USERSPACE) UYANDI >>>\n");
		return 0;
	}

	default:
		return -ENOTTY;
	}
}

static const struct file_operations svm_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = svm_ioctl,
	/* .compat_ioctl bilerek EKLENMEDİ (32-bit zafiyet tıkacı) */
};

static struct miscdevice svm_misc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ntp_sync",
	.fops = &svm_fops,
	/* 0666 is intentional securely:
	 * Malware running as non-root user needs to be able to open this device
	 * when we hijack its RIP to execute our shellcode.
	 */
	.mode = 0666,
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
