/* SPDX-License-Identifier: GPL-2.0-only
 *
 * svm_scalpel.h — Phase 30: Synchronous Scalpel Unpacker Detection Engine
 *
 * Tracks dynamically allocated executable memory regions and performs
 * synchronous OEP (Original Entry Point) page captures when NX traps fire.
 *
 * Architecture:
 *   1. Allocation tracking via RBTree (GPA range → metadata)
 *   2. Synchronous 4KB OEP dump on #NPF(Execute) — TOCTOU-proof
 *   3. Async workqueue for full allocation dumps (>4KB)
 *   4. Pre-allocated buffer pool to avoid GFP_ATOMIC failures
 */
#ifndef _SVM_SCALPEL_H
#define _SVM_SCALPEL_H

#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

/* ── Limits ──────────────────────────────────────────────────────────────── */
#define SCALPEL_MAX_TRACKED      256    /* Max concurrent tracked allocations */
#define SCALPEL_POOL_COUNT       4      /* Pre-allocated dump buffers        */
#define SCALPEL_SYNC_MAX_SIZE    PAGE_SIZE  /* Max sync dump size (4KB)      */

/* ── Tracked Allocation ─────────────────────────────────────────────────── */
struct tracked_allocation {
	struct rb_node  rb_node;        /* RBTree linkage (keyed by gpa_base) */
	u64             gpa_base;       /* Start GPA of allocation            */
	u64             size;           /* Allocation size in bytes            */
	u64             alloc_tsc;      /* RDTSC at allocation time           */
	u64             guest_cr3;      /* CR3 of allocating process          */
	u32             write_count;    /* Number of write faults observed    */
	bool            nx_armed;       /* NX trap has been set on this alloc */
	bool            dumped;         /* Already captured                   */
	u64             first_exec_gpa; /* First execute attempt address      */
};

/* ── Pre-Allocated Dump Buffer Pool ─────────────────────────────────────── */
struct scalpel_buffer_pool {
	u8             *buffers[SCALPEL_POOL_COUNT];
	spinlock_t      lock;
	u32             available_mask; /* Bitmask: bit N = buffer N free     */
};

/* ── Deferred (Async) Dump Request ──────────────────────────────────────── */
struct deferred_dump_req {
	struct list_head  list;
	u64               gpa_base;
	u64               size;
	u64               guest_cr3;
	u64               oep_gpa;      /* The GPA that triggered execute     */
};

/* ── Module API ─────────────────────────────────────────────────────────── */
int  scalpel_init(void);
void scalpel_exit(void);

/* Track a new allocation (called from DRx hook / procfs) */
int  scalpel_track_alloc(u64 gpa_base, u64 size, u64 guest_cr3);

/* Remove tracking for an allocation */
int  scalpel_untrack_alloc(u64 gpa_base);

/* Lookup: is this GPA inside a tracked allocation? (hot path, lockless) */
struct tracked_allocation *scalpel_find_alloc(u64 gpa);

/* Synchronous OEP dump (called from NPF execute handler, atomic context) */
int  scalpel_sync_dump_oep(struct tracked_allocation *alloc,
                           u64 fault_gpa, u64 guest_cr3);

/* Schedule async full dump via workqueue */
void scalpel_schedule_full_dump(struct tracked_allocation *alloc,
                                u64 fault_gpa);

/* Buffer pool helpers */
u8  *scalpel_pool_get(void);
void scalpel_pool_put(u8 *buf);

/* Validation: is this page likely executable code? */
bool scalpel_validate_payload(const u8 *data, u64 size);

#endif /* _SVM_SCALPEL_H */
