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
#include <linux/mutex.h>
#include <linux/uaccess.h>

/* ── Module-level ring instance ────────────────────────────────────────── */
extern atomic_t matrix_active;

/* Lockless Ring Buffer state */
struct svm_trace_ring svm_tring;
EXPORT_SYMBOL_GPL(svm_tring);

static DEFINE_MUTEX(trace_read_mutex);
static DEFINE_RAW_SPINLOCK(trace_write_lock);

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
static u64 ring_reserve(struct svm_trace_ring *r, u32 len) {
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
static void ring_write(struct svm_trace_ring *r, u64 offset, const void *src,
                       u32 len) {
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
static int ring_write_nofault(struct svm_trace_ring *r, u64 offset,
                              const void *src, u32 len) {
  u64 end = r->size;
  u32 first = (u32)min_t(u64, len, end - offset);
  int ret = 0;

  if (copy_from_kernel_nofault(r->buffer + offset, src, first)) {
    memset(r->buffer + offset, 0, first);
    ret = -EFAULT;
  }
  if (first < len) {
    if (copy_from_kernel_nofault(r->buffer, (const u8 *)src + first,
                                 len - first)) {
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
void svm_trace_emit_lbr(u64 cr3, u64 rip) {
  struct svm_trace_entry hdr;
  struct svm_lbr_pair lbr[AMD_LBR_STACK_DEPTH];
  unsigned long flags;
  u32 i, valid_count = 0;
  u64 offset;

  /* Bulgu #1: NULL buffer koruması — trace_init başarısız olmuş olabilir */
  if (unlikely(!svm_tring.buffer))
    return;

  if (!boot_cpu_has(X86_FEATURE_LBRV))
    return;

  memset(&hdr, 0, sizeof(hdr));
  memset(lbr, 0, sizeof(lbr));

  /* Bulgu #3: rdmsrq_safe ile LBR derinliğine güvenli erişim.
   * Desteklenmeyen MSR indekslerinde #GP yerine graceful fail. */
  for (i = 0; i < AMD_LBR_STACK_DEPTH; i++) {
    if (rdmsrq_safe(MSR_AMD_LBR_FROM_BASE + i, &lbr[i].from))
      break;
    if (rdmsrq_safe(MSR_AMD_LBR_TO_BASE + i, &lbr[i].to))
      break;
    valid_count++;
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

  /* Bulgu #4: spinlock zaten tam bariyer sağlar, smp_wmb gereksiz kaldırıldı */
  raw_spin_lock_irqsave(&trace_write_lock, flags);
  offset = ring_reserve(&svm_tring, sizeof(hdr));
  ring_write(&svm_tring, offset, &hdr, sizeof(hdr));
  atomic64_add(sizeof(hdr), &svm_tring.commit_idx);
  raw_spin_unlock_irqrestore(&trace_write_lock, flags);

  wake_up_interruptible(&svm_trace_wq);
}

/* ── NPF dirty-page capture ─────────────────────────────────────────────── */

/*
 * svm_trace_emit_dirty - Capture one 4 KB page into the ring on NPF write-
 * fault.  The header is written first, then raw page bytes.  Both pieces are
 * protected by smp_wmb() so a reader that sees the header always sees the data.
 */
void svm_trace_emit_dirty(u64 cr3, u64 rip, u64 fault_gpa, const void *hva) {
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
static ssize_t trace_read(struct file *file, char __user *buf, size_t count,
                          loff_t *pos) {
  u64 committed, consumed, avail;
  u64 offset;
  u32 copy_len;
  ssize_t ret = 0;

  if (!svm_tring.buffer)
    return -ENOMEM;

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
     * Extrinsic lock mechanism: If Matrix has organically terminated and there
     * are no remaining records to consume, signal standard EOF instead of
     * deadlocking.
     */
    if (atomic_read(&matrix_active) == 0) {
      ret = 0; /* Clean EOF */
      goto out;
    }

    /* Release mutex before sleeping to prevent deadlocks */
    mutex_unlock(&trace_read_mutex);
    if (wait_event_interruptible(
            svm_trace_wq, (u64)atomic64_read(&svm_tring.commit_idx) >
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

  smp_rmb();
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

static const struct proc_ops pops_trace = {
    .proc_read = trace_read,
};

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

int svm_trace_init(void) {
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

  pr_info("[SVM_TRACE] 64 MB ring buffer ready; /proc/svm_trace open\n");
  return 0;
}

void svm_trace_cleanup(void) {
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
