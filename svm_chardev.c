// SPDX-License-Identifier: GPL-2.0-only
/*
 * Character Device for Ghost Injection (Matrix Portal)
 *
 * Manges /dev/ntp_sync, allowing injected processes to voluntarily enter
 * the VMRUN sandbox without exposing PTRACE footprint.
 */

#include "ring_minus_one.h"
#include "npt_walk.h"
#include "svm_trace.h"
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
pid_t matrix_owner_pid;

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

			/*
			 * [PHASE 19 V2] CPU pin kaldırıldı!
			 * Hedef artık tüm core'larda koşabilir.
			 * Her VMRUN öncesi o anki core'un VMCB'si kullanılır.
			 */

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

			/* Session state kaydı (migration için) */
			g_svm->session_cr3 = __pa(current->mm->pgd);
			g_svm->session_rip = uregs->ip;
			g_svm->session_rsp = uregs->sp;
			g_svm->session_rflags = (uregs->flags & 0xFFFFFFFFFFFFFCD5ULL) | 2;
			g_svm->session_rax = 1; /* Quantum fork return */
			g_svm->last_cpu = -1;   /* İlk VMRUN'da hazırlanmasını zorla */

			g_target_cr3 = g_svm->session_cr3;

			pr_info("[NTP_SYNC] >>> GHOST THREAD '%s' EVREN KOPYALANIYOR... <<<\n",
				current->comm);
		} else {
			/*
			 * RESUMING from a Userspace Syscall Trampoline!
			 */
			if (atomic_read(&matrix_active) != 1 ||
			    matrix_owner_pid != current->pid) {
				pr_warn("[NTP_SYNC] Resume denied: not owner! PID: %d (owner: %d)\n",
					current->pid, matrix_owner_pid);
				return -EINVAL;
			}
			
			/*
			 * CRITICAL FIX: Pass the syscall result back into the Guest CPU!
			 * The userspace trampoline executed the syscall for the guest, and placed
			 * the return value in k_exit_info.rax. We must inject it into the Guest!
			 */
			g_svm->session_rax = k_exit_info.rax;
			k_exit_info.exit_reason = MATRIX_EXIT_REASON_NONE;
			
			/* VMCB update will be cleanly handled inside the VMRUN loop via disabled preemption */
		}

		/* ─── VMRUN HYPERVISOR LOOP (Migration-Aware) ─── */
		u64 iter_count = 0;
		while (1) {
			int cpu;
			struct percpu_vmcb *pv;
			struct vmcb *vmcb;

			/*
			 * Kill Switch 3: Global Execution Timeout (Soft-Lockguard Guard)
			 * Guest 50 milyon denemede halen userspace'e uyanamadıysa
			 * makineyi dondurmamak için zorla çıkart.
			 */
			if (++iter_count > 50000000ULL) {
				pr_emerg("[MATRIX] *** KILL SWITCH: GLOBAL LOOP TIMEOUT EXCEEDED! Ejecting. ***\n");
				ret_loop = -ETIME;
				break;
			}

			if (signal_pending(current)) {
				pr_info("[NTP_SYNC] Thread caught signal, exiting Matrix.\n");
				ret_loop = -EINTR;
				break;
			}

			cpu = get_cpu(); /* Preemption kapalı — core değişemez */
			pv = per_cpu_ptr(&cpu_vmcbs, cpu);
			vmcb = pv->vmcb;

			/* CPU migration tespiti: farklı core'a mı düştük? */
			if (cpu != g_svm->last_cpu) {
				g_svm->last_cpu = cpu;
				g_svm->vmcb = pv->vmcb;
				g_svm->vmcb_pa = pv->vmcb_pa;

				/* VMCB'yi bu core'un host state'i ile hazırla */
				ret_loop = vmcb_prepare_npt(g_svm,
							    g_svm->session_rip,
							    g_svm->session_rsp,
							    g_svm->session_cr3);
				if (ret_loop) {
					put_cpu();
					break;
				}

				/* Guest execution state'i geri yükle */
				g_svm->vmcb->save.rax = g_svm->session_rax;
				g_svm->vmcb->save.rflags = g_svm->session_rflags;

				/* NPT kickstart (sadece ilk entry) */
				if (g_svm->last_cpu < 0)
					npt_set_page_ro(&g_svm->npt,
							g_svm->session_rsp & PAGE_MASK);

				/* Pending NPT rearm (TF/DB) devam ettir */
				if (g_svm->pending_rearm_gpa) {
					g_svm->vmcb->save.rflags |= (1ULL << 8); /* TF */
					g_svm->vmcb->control.intercepts[INTERCEPT_EXCEPTION_OFFSET >> 5] |=
					    (1U << 1); /* #DB */
					g_svm->vmcb->control.clean &=
					    ~VMCB_CLEAN_INTERCEPTS;
				}

				g_svm->vmcb->control.clean = 0; /* Full reload */

				pr_info_ratelimited("[NTP_SYNC] VMCB migrated to CPU %d\n", cpu);
			}

			ret_loop = svm_run_guest(g_svm, &g_svm->gregs);

			/* Guest state'i kaydet (olası migration için) */
			g_svm->session_rip = g_svm->vmcb->save.rip;
			g_svm->session_rsp = g_svm->vmcb->save.rsp;
			g_svm->session_rax = g_svm->vmcb->save.rax;
			g_svm->session_rflags = g_svm->vmcb->save.rflags;

			put_cpu(); /* Preemption açık — scheduler göç yapabilir */

			if (ret_loop != 0)
				break;

			cond_resched();
		}

		/* ─── EXIT & RESTORE ─── */
		/* Phase 26: Complete chronological preservation of batches */
		svm_trace_flush_batch();

		/*
		 * CRITICAL FIX: Keep session_rip/rsp up to date! 
		 * If we exit to trampoline (ret_loop == 2), and later resume on a DIFFERENT CPU, 
		 * vmcb_prepare_npt will use session_rip! If we don't update it here, the guest
		 * loops infinitely back to the start!
		 */
		g_svm->session_rip = g_svm->vmcb->save.rip;
		g_svm->session_rsp = g_svm->vmcb->save.rsp;

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
		 * Guest SYSCALL path'inde kernel RIP meşrudur.
		 * Sadece VMRUN loop'u hata ile çıktıysa (ret_loop < 0)
		 * ve guest userspace'e dönemeden kaldıysa kontrol et.
		 */
		if (ret_loop < 0 &&
		    g_svm->session_rip >= TASK_SIZE_MAX) {
			pr_err("[NTP_SYNC] SECURITY: LPE Exploit detected! RIP=0x%llx Terminating PID %d\n",
			       g_svm->session_rip, current->pid);
			force_sig(SIGKILL);

			atomic_set(&matrix_active, 0);
			wake_up_interruptible(&svm_trace_wq);
			return -EPERM;
		}

		// REAL EXIT: We are aborting or permanently returning to target
		if (!has_u_exit_info) {
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

static int ntp_sync_release(struct inode *inode, struct file *file)
{
	/*
	 * Eğer bu file descriptor'ı kapatan process Matrix'in asıl sahibiyse ve
	 * hala active durumda kaldıysa (örneğin Syscall Trampoline'dan return yerine
	 * direkt native exit() yaptıysa veya SIGKILL yediyse), kilidi zorla aç.
	 */
	if (atomic_read(&matrix_active) == 1 && matrix_owner_pid == current->pid) {
		atomic_set(&matrix_active, 0);
		wake_up_interruptible(&svm_trace_wq);
		pr_info("[NTP_SYNC] Zombie Matrix session cleaned up for PID: %d\n", current->pid);
	}
	return 0;
}

static const struct file_operations svm_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = svm_ioctl,
	.release = ntp_sync_release,
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
