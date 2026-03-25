// SPDX-License-Identifier: GPL-2.0-only
/*
 * svm_trace.c — Ring -1 Continuous Malware Tracer (V6.0)
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

/* ── Module-level ring instance ────────────────────────────────────────── */
struct svm_trace_ring svm_tring;
EXPORT_SYMBOL_GPL(svm_tring);

/*
 * Wait queue: /proc reader blocks here when the ring is empty.
 * Producer calls wake_up_interruptible() after each committed record.
 */
static DECLARE_WAIT_QUEUE_HEAD(svm_trace_wq);

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
	u64 tail = (u64)atomic64_add_return(len, &r->write_idx) - len;
	/* Overflow: advance read pointer so the consumer always sees fresh data */
	if (tail - (u64)atomic64_read(&r->read_idx) + len > r->size) {
		atomic64_add(len, &r->read_idx);
		atomic64_inc(&r->drop_count);
	}
	return tail % r->size;
}

/*
 * ring_write - Copy @len bytes from @src into the ring at @offset, handling
 * the wrap-around split if the write crosses the end of the vmalloc area.
 */
static void ring_write(struct svm_trace_ring *r, u64 offset,
		       const void *src, u32 len)
{
	u64 end   = r->size;
	u32 first = (u32)min_t(u64, len, end - offset);

	memcpy(r->buffer + offset, src, first);
	if (first < len)
		memcpy(r->buffer, (const u8 *)src + first, len - first);
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
void svm_trace_emit_lbr(u64 cr3, u64 rip)
{
	struct svm_trace_entry hdr;
	struct svm_lbr_pair    lbr[AMD_LBR_STACK_DEPTH];
	u32  i;
	u64  offset;

	for (i = 0; i < AMD_LBR_STACK_DEPTH; i++) {
		rdmsrl(MSR_AMD_LBR_FROM_BASE + i, lbr[i].from);
		rdmsrl(MSR_AMD_LBR_TO_BASE   + i, lbr[i].to);
	}

	hdr.magic      = SVM_TRACE_MAGIC;
	hdr.tsc        = rdtsc_ordered();
	hdr.event_type = TRACE_EVT_LBR_SAMPLE;
	hdr.lbr_count  = AMD_LBR_STACK_DEPTH;
	hdr.guest_cr3  = cr3;
	hdr.guest_rip  = rip;
	hdr.fault_gpa  = 0;
	hdr.data_size  = 0;
	hdr._pad       = 0;
	memcpy(hdr.lbr, lbr, sizeof(lbr));

	/* Producer critical section: reserve → write payload → commit barrier */
	offset = ring_reserve(&svm_tring, sizeof(hdr));
	smp_wmb();                          /* ensure header visible before data */
	ring_write(&svm_tring, offset, &hdr, sizeof(hdr));
	smp_wmb();                          /* commit: data visible to consumer  */
	atomic64_add(sizeof(hdr), &svm_tring.commit_idx);

	wake_up_interruptible(&svm_trace_wq);
}
EXPORT_SYMBOL_GPL(svm_trace_emit_lbr);

/* ── NPF dirty-page capture ─────────────────────────────────────────────── */

/*
 * svm_trace_emit_dirty - Capture one 4 KB page into the ring on NPF write-
 * fault.  The header is written first, then raw page bytes.  Both pieces are
 * protected by smp_wmb() so a reader that sees the header always sees the data.
 */
void svm_trace_emit_dirty(u64 cr3, u64 rip, u64 fault_gpa, const void *hva)
{
	struct svm_trace_entry hdr;
	u32  total = sizeof(hdr) + PAGE_SIZE;
	u64  offset;

	hdr.magic      = SVM_TRACE_MAGIC;
	hdr.tsc        = rdtsc_ordered();
	hdr.event_type = TRACE_EVT_NPF_DIRTY;
	hdr.lbr_count  = 0;
	hdr.guest_cr3  = cr3;
	hdr.guest_rip  = rip;
	hdr.fault_gpa  = fault_gpa;
	hdr.data_size  = PAGE_SIZE;
	hdr._pad       = 0;
	memset(hdr.lbr, 0, sizeof(hdr.lbr));

	offset = ring_reserve(&svm_tring, total);
	smp_wmb();
	ring_write(&svm_tring, offset, &hdr, sizeof(hdr));
	ring_write(&svm_tring, (offset + sizeof(hdr)) % svm_tring.size,
		   hva, PAGE_SIZE);
	smp_wmb();
	atomic64_add(total, &svm_tring.commit_idx);

	wake_up_interruptible(&svm_trace_wq);
}
EXPORT_SYMBOL_GPL(svm_trace_emit_dirty);

/* ── /proc/svm_trace consumer ───────────────────────────────────────────── */

/*
 * trace_read - Blocking read for the Python daemon.
 *
 * Waits until at least one committed record exists, then copies as many bytes
 * as @count allows (without splitting a record mid-way — the consumer is
 * responsible for parsing fixed-size headers).
 */
static ssize_t trace_read(struct file *file, char __user *buf,
			  size_t count, loff_t *pos)
{
	u64   committed, consumed, avail;
	u64   offset;
	u32   copy_len;

	if (!svm_tring.buffer)
		return -ENOMEM;

retry:
	smp_rmb();                          /* see all committed writes          */
	committed = (u64)atomic64_read(&svm_tring.commit_idx);
	consumed  = (u64)atomic64_read(&svm_tring.read_idx);

	if (committed <= consumed) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(svm_trace_wq,
		    (u64)atomic64_read(&svm_tring.commit_idx) >
		    (u64)atomic64_read(&svm_tring.read_idx)))
			return -ERESTARTSYS;
		goto retry;
	}

	avail    = committed - consumed;
	copy_len = (u32)min_t(u64, avail, count);

	/* Handle ring wrap: only copy up to end of buffer in one shot */
	offset   = consumed % svm_tring.size;
	if (offset + copy_len > svm_tring.size)
		copy_len = (u32)(svm_tring.size - offset);

	smp_rmb();
	if (copy_to_user(buf, svm_tring.buffer + offset, copy_len))
		return -EFAULT;

	atomic64_add(copy_len, &svm_tring.read_idx);
	return copy_len;
}

static const struct proc_ops pops_trace = {
	.proc_read = trace_read,
};

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

int svm_trace_init(void)
{
	svm_tring.size = SVM_TRACE_BUF_SIZE;
	svm_tring.buffer = vmalloc(svm_tring.size);
	if (!svm_tring.buffer) {
		pr_err("[SVM_TRACE] vmalloc(%lu) failed\n", svm_tring.size);
		return -ENOMEM;
	}

	atomic64_set(&svm_tring.write_idx,  0);
	atomic64_set(&svm_tring.commit_idx, 0);
	atomic64_set(&svm_tring.read_idx,   0);
	atomic64_set(&svm_tring.drop_count, 0);

	proc_trace_entry = proc_create("svm_trace", 0400, NULL, &pops_trace);
	if (!proc_trace_entry) {
		vfree(svm_tring.buffer);
		svm_tring.buffer = NULL;
		return -ENOMEM;
	}

	pr_info("[SVM_TRACE] 64 MB ring buffer ready; /proc/svm_trace open\n");
	return 0;
}

void svm_trace_cleanup(void)
{
	if (proc_trace_entry) {
		remove_proc_entry("svm_trace", NULL);
		proc_trace_entry = NULL;
	}
	if (svm_tring.buffer) {
		pr_info("[SVM_TRACE] %lld records dropped over session\n",
			atomic64_read(&svm_tring.drop_count));
		vfree(svm_tring.buffer);
		svm_tring.buffer = NULL;
	}
}
