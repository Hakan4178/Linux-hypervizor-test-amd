/* SPDX-License-Identifier: GPL-2.0-only
 *
 * svm_trace.h — Ring -1 Continuous Malware Tracer — V6.0
 *
 * Defines the shared ABI between the trace producer (vmexit.c / NPF handler)
 * and the consumer (/proc/svm_trace + Python CLI).  Every struct written into
 * the ring buffer starts with svm_trace_entry; variable-length page payloads
 * are appended immediately after.
 */
#ifndef _SVM_TRACE_H
#define _SVM_TRACE_H

#include "ring_minus_one.h"   /* pulls all kernel + ASM headers */

/* ── Ring buffer dimensions ─────────────────────────────────────────────── */
#define SVM_TRACE_BUF_SIZE     (64UL * 1024 * 1024)   /* 64 MB vmalloc area */
#define SVM_TRACE_MAGIC        0x5356545200000000ULL   /* 'SVTR\0\0\0\0'     */

/* ── AMD64 LBR MSR layout (Family 15h/17h) ──────────────────────────────── */
#define AMD_LBR_STACK_DEPTH    16          /* AMD Zen 2/3 has 16 LBR entries */
#define MSR_AMD_LBR_FROM_BASE  0xC0000060UL
#define MSR_AMD_LBR_TO_BASE    0xC0000080UL

/* ── Event types ─────────────────────────────────────────────────────────── */
#define TRACE_EVT_LBR_SAMPLE   1   /* Periodic LBR drain: hot-code tick       */
#define TRACE_EVT_NPF_DIRTY    2   /* NPT write-fault: page mutated           */
#define TRACE_EVT_MTF_REARM    3   /* MTF single-step completed; page re-RO'd */

/*
 * svm_lbr_pair - One FROM→TO branch record captured from hardware MSRs.
 */
struct svm_lbr_pair {
	u64 from;
	u64 to;
} __attribute__((packed));

/*
 * svm_trace_entry - Fixed-size header prepended to every ring record.
 *
 * If event_type == TRACE_EVT_NPF_DIRTY, exactly @data_size bytes of raw page
 * data follow immediately after this header in the ring (4096 for a full 4KB
 * page capture).  For LBR events the lbr[] array below carries everything and
 * data_size == 0.
 */
struct svm_trace_entry {
	u64 magic;              /* SVM_TRACE_MAGIC sanity sentinel           */
	u64 tsc;                /* RDTSC at capture time                     */
	u32 event_type;         /* TRACE_EVT_*                               */
	u32 lbr_count;          /* valid entries in lbr[] (0 for dirty-page) */
	u64 guest_cr3;          /* guest page-table root at time of exit     */
	u64 guest_rip;          /* guest instruction pointer                 */
	u64 fault_gpa;          /* faulting GPA (NPF events only)            */
	u32 data_size;          /* byte size of appended payload             */
	u32 _pad;
	struct svm_lbr_pair lbr[AMD_LBR_STACK_DEPTH]; /* hot-code evidence */
} __attribute__((packed));

/*
 * svm_trace_ring - Lockless SPSC ring buffer.
 *
 * Producer (VMEXIT handler, non-preemptible context):
 *   atomic64_add write_idx; smp_wmb(); write payload; smp_wmb(); commit.
 * Consumer (/proc read, process context):
 *   smp_rmb(); read payload; smp_rmb(); advance read_idx.
 *
 * Overflow policy: newest event overwrites oldest (lossy).  MTF and NPF paths
 * are hot, so we never sleep or spin waiting for drain.
 */
struct svm_trace_ring {
	u8 __iomem *buffer;
	atomic64_t   write_idx;
	atomic64_t   commit_idx;  /* visible to consumer only after wmb()    */
	atomic64_t   read_idx;
	size_t       size;
	atomic64_t   drop_count;  /* number of records lost to overflow      */
};

extern struct svm_trace_ring svm_tring;

/* ── Public API ─────────────────────────────────────────────────────────── */

int  svm_trace_init(void);
void svm_trace_cleanup(void);

/*
 * svm_trace_emit_lbr - Drain hardware LBR stack and emit one TRACE_EVT_LBR_SAMPLE
 * record.  Called from the periodic VMEXIT tick inside vmexit.c.
 * @cr3:  guest CR3 at time of exit
 * @rip:  guest RIP at time of exit
 */
void svm_trace_emit_lbr(u64 cr3, u64 rip);

/*
 * svm_trace_emit_dirty - Record a 4KB dirty page caught by the NPT write-fault
 * handler.  Called while still inside the VMEXIT path (IRQs off/Guest stopped).
 * @cr3:     guest CR3
 * @rip:     faulting guest RIP
 * @fault_gpa: guest physical address of the faulting page (4KB aligned)
 * @hva:      kernel virtual address of the page to copy
 */
void svm_trace_emit_dirty(u64 cr3, u64 rip, u64 fault_gpa, const void *hva);

#endif /* _SVM_TRACE_H */
