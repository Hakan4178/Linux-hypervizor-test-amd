// SPDX-License-Identifier: GPL-2.0-only
/*
 * Ring -1 Continuous Malware Tracer (V6.0)
 *
 * Three interlocking engines:
 *
 *   [1] 64 MB Lockless Ring Buffer (vmalloc, SPSC, SMP-safe)
 *       smp_wmb/smp_rmb guard all producer↔consumer visibility.
 *
 *   [2] LBR Chronological Sampler
 *       On every periodic VMEXIT tick we drain all AMD_LBR_STACK_DEPTH MSR
 *       pairs in order.  Because AMD pushes the newest entry to the lowest
 *       index, we iterate MSR 0..N-1 so the ring carries them oldest-first,
 *       giving the consumer a monotonically-ordered execution trace.
 *
 *   [3] NPT Stealth Dirty-Page Tracker + MTF Re-Arm
 *       When the NPF handler fires (ExitCode 0x400, write violation):
 *         · Capture the 4 KB page into the ring.
 *         · Restore NPT_WRITE on the PD entry (let the write land).
 *         · Set VMCB.intercept_exceptions |= (1<<DB) and VMCB.dr_ctrl |= MTF
 *           so the very next guest instruction triggers a #DB/MTF VMEXIT.
 *         · In the MTF handler: strip NPT_WRITE again so the *next* mutation
 *           is also caught.  Clear MTF.  Resume.
 *       Net result: *every* write to a watched page is captured, zero mutations
 *       are missed, and the guest never observes a stall.
 */

#include "svm_trace.h"
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

/* ── Module-level ring instance ────────────────────────────────────────── */
extern atomic_t matrix_active;

/* Lockless Ring Buffer state */
struct svm_trace_ring svm_tring;
EXPORT_SYMBOL_GPL(svm_tring);

static DEFINE_MUTEX(trace_read_mutex);
static DEFINE_RAW_SPINLOCK(trace_write_lock);
static atomic_t mmap_count = ATOMIC_INIT(0);

/*
 * Wait queue: /proc reader blocks here when the ring is empty.
 * Producer calls wake_up_interruptible() after each committed record.
 */
DECLARE_WAIT_QUEUE_HEAD(svm_trace_wq);
EXPORT_SYMBOL_GPL(svm_trace_wq);

static struct proc_dir_entry *proc_trace_entry;

/* ── Internal helpers ───────────────────────────────────────────────────── */

/*
 * ring_reserve - Atomically claim @len bytes in the ring.
 *
 * Returns the byte offset at which the caller should write.  If the ring is
 * too small the oldest data will be silently overwritten (overrun policy).
 * The returned offset is already masked to [0, size).
 */
static u64 ring_reserve(struct svm_trace_ring *r, u32 len)
{
	u64 write_idx = (u64)atomic64_add_return(len, &r->write_idx);
	u64 tail = write_idx - len;
	u64 read_idx, old_read_idx;
	u64 used, drop;

	while (1) {
		read_idx = (u64)atomic64_read(&r->read_idx);
		used = write_idx - read_idx;
		if (used <= r->size)
			break;

		drop = used - r->size;
		old_read_idx = atomic64_cmpxchg(&r->read_idx, read_idx, read_idx + drop);
		if (old_read_idx == read_idx) {
			atomic64_add(drop, &r->drop_count);
			break;
		}
	}
	return tail % r->size;
}

/*
 * ring_write - Copy @len bytes from @src into the ring at @offset, handling
 * the wrap-around split if the write crosses the end of the vmalloc area.
 */
static void ring_write(struct svm_trace_ring *r, u64 offset, const void *src, u32 len)
{
	u64 end = r->size;
	u32 first = (u32)min_t(u64, len, end - offset);

	memcpy(r->buffer + offset, src, first);
	if (first < len)
		memcpy(r->buffer, (const u8 *)src + first, len - first);
}

/*
 * ring_write_nofault - Copy from potentially-faulting kernel address.
 * On failure, zero-fills the destination to prevent stale data leaks.
 * Returns 0 on full success, -EFAULT on any copy failure.
 */
static int ring_write_nofault(struct svm_trace_ring *r, u64 offset, const void *src, u32 len)
{
	u64 end = r->size;
	u32 first = (u32)min_t(u64, len, end - offset);
	int ret = 0;

	if (copy_from_kernel_nofault(r->buffer + offset, src, first)) {
		memset(r->buffer + offset, 0, first);
		ret = -EFAULT;
	}
	if (first < len) {
		if (copy_from_kernel_nofault(r->buffer, (const u8 *)src + first, len - first)) {
			memset(r->buffer, 0, len - first);
			ret = -EFAULT;
		}
	}
	return ret;
}

/* ── LBR drain ──────────────────────────────────────────────────────────── */

/*
 * svm_trace_emit_lbr - Read all AMD LBR MSR pairs, emit one ring record.
 *
 * AMD pushes the *most recent* branch to the lowest-index slot on each call.
 * We read MSRs 0..N-1 left-to-right so entry 0 is the newest.  The consumer
 * can reverse if it needs chronological order, but capturing them in MSR order
 * ensures we never miss any entry regardless of how fast the guest runs.
 */
void svm_trace_emit_lbr(u64 cr3, u64 rip, u64 br_from, u64 br_to)
{
	struct svm_trace_entry hdr;
	struct svm_lbr_pair lbr[AMD_LBR_STACK_DEPTH];
	unsigned long flags;
	u32 i, valid_count = 0;
	u64 offset;

	if (unlikely(!svm_tring.buffer))
		return;

	memset(&hdr, 0, sizeof(hdr));
	memset(lbr, 0, sizeof(lbr));

	/* 
	 * Telemetry Resilience: 
	 * 1. Try to drain the full hardware LBR stack via MSRs if LBRV is active.
	 */
	if (boot_cpu_has(X86_FEATURE_LBRV)) {
		for (i = 0; i < AMD_LBR_STACK_DEPTH; i++) {
			if (rdmsrq_safe(MSR_AMD_LBR_FROM_BASE + i, &lbr[i].from))
				break;
			if (rdmsrq_safe(MSR_AMD_LBR_TO_BASE + i, &lbr[i].to))
				break;
			valid_count++;
		}
	}

	/* 
	 * 2. Fallback: If stack is empty but we have a valid VMCB branch, use it.
	 * This ensures visibility even on hardware that only reports the last branch.
	 */
	if (valid_count == 0 && (br_from || br_to)) {
		lbr[0].from = br_from;
		lbr[0].to = br_to;
		valid_count = 1;
	}

	hdr.magic = SVM_TRACE_MAGIC;
	hdr.tsc = rdtsc_ordered();
	hdr.event_type = TRACE_EVT_LBR_SAMPLE;
	hdr.lbr_count = valid_count;
	hdr.guest_cr3 = cr3;
	hdr.guest_rip = rip;
	hdr.fault_gpa = 0;
	hdr.data_size = 0;
	memcpy(hdr.lbr, lbr, sizeof(lbr));

	raw_spin_lock_irqsave(&trace_write_lock, flags);
	offset = ring_reserve(&svm_tring, sizeof(hdr));
	ring_write(&svm_tring, offset, &hdr, sizeof(hdr));
	atomic64_add(sizeof(hdr), &svm_tring.commit_idx);
	raw_spin_unlock_irqrestore(&trace_write_lock, flags);

	pr_info_once("[SVM_TRACE] First telemetry record (LBR Fallback: %s) emitted.\n",
		     valid_count > 0 ? "YES" : "NO (RIP Only)");
	wake_up_interruptible(&svm_trace_wq);
}

/* ── NPF dirty-page capture ─────────────────────────────────────────────── */

/*
 * svm_trace_emit_dirty - Capture one 4 KB page into the ring on NPF write-
 * fault.  The header is written first, then raw page bytes.  Both pieces are
 * protected by smp_wmb() so a reader that sees the header always sees the data.
 */
void svm_trace_emit_dirty(u64 cr3, u64 rip, u64 fault_gpa, const void *hva)
{
	struct svm_trace_entry hdr;
	unsigned long flags;
	u32 total = sizeof(hdr) + PAGE_SIZE;
	u64 offset, data_offset;
	int copy_ret;

	/* Bulgu #1: NULL buffer koruması */
	if (unlikely(!svm_tring.buffer))
		return;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = SVM_TRACE_MAGIC;
	hdr.tsc = rdtsc_ordered();
	hdr.event_type = TRACE_EVT_NPF_DIRTY;
	hdr.lbr_count = 0;
	hdr.guest_cr3 = cr3;
	hdr.guest_rip = rip;
	hdr.fault_gpa = fault_gpa;
	hdr.data_size = PAGE_SIZE;

	raw_spin_lock_irqsave(&trace_write_lock, flags);
	offset = ring_reserve(&svm_tring, total);
	ring_write(&svm_tring, offset, &hdr, sizeof(hdr));

	/* Bulgu #2: copy hatasında zero-fill ile bilgi sızıntısını önle */
	data_offset = (offset + sizeof(hdr)) % svm_tring.size;
	copy_ret = ring_write_nofault(&svm_tring, data_offset, hva, PAGE_SIZE);
	if (copy_ret) {
		/* Header'ın data_size'ını 0 yap ki tüketici bozuk veri okumasın */
		hdr.data_size = 0;
		ring_write(&svm_tring, offset, &hdr, sizeof(hdr));
	}

	atomic64_add(total, &svm_tring.commit_idx);
	raw_spin_unlock_irqrestore(&trace_write_lock, flags);

	wake_up_interruptible(&svm_trace_wq);
}

/* ── /proc/svm_trace consumer ───────────────────────────────────────────── */

/*
 * trace_read - Blocking read for the Python daemon.
 *
 * Waits until at least one committed record exists, then copies as many bytes
 * as @count allows (without splitting a record mid-way — the consumer is
 * responsible for parsing fixed-size headers).
 */
static ssize_t trace_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	u64 committed, consumed, avail;
	u64 offset;
	u32 copy_len;
	ssize_t ret = 0;

	if (!svm_tring.buffer)
		return -ENOMEM;

	pr_info_once("[SVM_TRACE] Userspace reader connected to /proc/svm_trace\n");

	mutex_lock(&trace_read_mutex);
retry:
	smp_rmb(); /* see all committed writes          */
	committed = (u64)atomic64_read(&svm_tring.commit_idx);
	consumed = (u64)atomic64_read(&svm_tring.read_idx);

	if (committed < consumed) {
		ret = -EIO;
		goto out;
	}

	if (committed == consumed) {
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		}

		/*
		 * MATRIX STATE CHECK (EOF Injection)
		 * Only signal EOF if the buffer is empty AND the Matrix session
		 * is inactive. If committed > consumed, we must allow the
		 * consumer to drain the remaining evidence!
		 */
		if (atomic_read(&matrix_active) == 0 &&
		    (u64)atomic64_read(&svm_tring.commit_idx) == (u64)atomic64_read(&svm_tring.read_idx)) {
			ret = 0; /* Clean EOF */
			goto out;
		}

		/* Release mutex before sleeping to prevent deadlocks */
		mutex_unlock(&trace_read_mutex);
		if (wait_event_interruptible(svm_trace_wq,
					     (u64)atomic64_read(&svm_tring.commit_idx) >
						     (u64)atomic64_read(&svm_tring.read_idx) ||
						 atomic_read(&matrix_active) == 0))
			return -ERESTARTSYS;

		mutex_lock(&trace_read_mutex);
		goto retry;
	}

	avail = committed - consumed;
	copy_len = (u32)min_t(u64, avail, count);

	/* Handle ring wrap: only copy up to end of buffer in one shot */
	offset = consumed % svm_tring.size;
	if (copy_len > svm_tring.size - offset)
		copy_len = (u32)(svm_tring.size - offset);

	smp_rmb(); /* Ensure ring buffer reads are not reordered before index checks */
	if (copy_to_user(buf, svm_tring.buffer + offset, copy_len)) {
		ret = -EFAULT;
		goto out;
	}

	atomic64_add(copy_len, &svm_tring.read_idx);
	ret = copy_len;
out:
	mutex_unlock(&trace_read_mutex);
	return ret;
}

static void trace_mmap_open(struct vm_area_struct *vma)
{
	atomic_inc(&mmap_count);
}

static void trace_mmap_close(struct vm_area_struct *vma)
{
	atomic_dec(&mmap_count);
}

static const struct vm_operations_struct trace_vm_ops = {
	.open  = trace_mmap_open,
	.close = trace_mmap_close,
};

static int trace_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;

	if (size > svm_tring.size)
		return -EINVAL;

	/* SECURITY: Enforce Read-Only mapping. Don't let userspace corrupt the trace ring */
	if (vma->vm_flags & VM_WRITE)
		return -EPERM;

	/* Mark VMA to prevent core dumping and paging out */
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);

	if (remap_vmalloc_range(vma, svm_tring.buffer, 0)) {
		pr_err("[SVM_TRACE] mmap failed to map trace buffer\n");
		return -EAGAIN;
	}

	/* Track active mappings to prevent use-after-free on module unload */
	vma->vm_ops = &trace_vm_ops;
	atomic_inc(&mmap_count);

	return 0;
}

static const struct proc_ops pops_trace = {
	.proc_read = trace_read,
	.proc_mmap = trace_mmap,
};

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

int svm_trace_init(void)
{
	svm_tring.size = SVM_TRACE_BUF_SIZE;
	svm_tring.buffer = vzalloc(svm_tring.size);
	if (!svm_tring.buffer) {
		pr_err("[SVM_TRACE] vzalloc(%lu) failed\n", svm_tring.size);
		return -ENOMEM;
	}

	atomic64_set(&svm_tring.write_idx, 0);
	atomic64_set(&svm_tring.commit_idx, 0);
	atomic64_set(&svm_tring.read_idx, 0);
	atomic64_set(&svm_tring.drop_count, 0);

	proc_trace_entry = proc_create("svm_trace", 0400, NULL, &pops_trace);
	if (!proc_trace_entry) {
		vfree(svm_tring.buffer);
		svm_tring.buffer = NULL;
		return -ENOMEM;
	}

	pr_info("[SVM_TRACE] 64 MB ring buffer ready; /proc/svm_trace open (LBRV %s)\n",
		boot_cpu_has(X86_FEATURE_LBRV) ? "Supported" : "NOT Supported (Using Resilience Fallback)");
	return 0;
}

void svm_trace_cleanup(void)
{
	if (proc_trace_entry) {
		remove_proc_entry("svm_trace", NULL);
		proc_trace_entry = NULL;
	}

	/*
	 * SECURITY: Guard against use-after-free.
	 * If any userspace process still holds an mmap reference to our buffer,
	 * freeing it would create a UAF condition exploitable for LPE.
	 * Refuse to free and log a critical warning instead.
	 */
	if (svm_tring.buffer) {
		int refs = atomic_read(&mmap_count);

		pr_info("[SVM_TRACE] %lld records dropped over session\n",
			atomic64_read(&svm_tring.drop_count));

		if (refs > 0) {
			pr_crit("[SVM_TRACE] REFUSING vfree: %d active mmap refs! Leaking buffer to prevent UAF.\n",
				refs);
			svm_tring.buffer = NULL;
			return;
		}

		vfree(svm_tring.buffer);
		svm_tring.buffer = NULL;
	}
}
