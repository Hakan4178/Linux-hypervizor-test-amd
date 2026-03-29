/*
 * ring_minus_one.h — Shared Header for Ring -1 Unified Engine V4.0
 *
 * All internal source files include this for shared types,
 * globals, and function prototypes.
 */
#ifndef RING_MINUS_ONE_H
#define RING_MINUS_ONE_H

#include <asm/desc.h>
#include <asm/fpu/api.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/special_insns.h>
#include <asm/svm.h>
#include <asm/tlbflush.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nmi.h>
#include <linux/percpu.h>
#include <linux/pid.h>
#include <linux/preempt.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "svm_dump.h"

/* ═══════════════════════════════════════════════════════════════════════════
 *  NPT — Tanımlar & Yapılar
 * ═══════════════════════════════════════════════════════════════════════════
 */

#define NPT_PRESENT (1ULL << 0)
#define NPT_WRITE (1ULL << 1)
#define NPT_USER (1ULL << 2)
#define NPT_PS (1ULL << 7)
#define NPT_NX (1ULL << 63)
#define NPT_DEFAULT_FLAGS (NPT_PRESENT | NPT_WRITE | NPT_USER)
#define NPT_MAX_PAGES 8192
#define NPT_PWT (1ULL << 3)
#define NPT_PCD (1ULL << 4)
#define NPT_PAT_LARGE (1ULL << 12)
#define NPT_CACHE_WB 0ULL
#define NPT_CACHE_UC (NPT_PWT | NPT_PCD)

/*
 * AMD-V VMCB Clean Bits (APM Vol.2 §15.15.4)
 * Setting a bit = "this field hasn't changed, skip reload"
 * We mark stable fields clean after first VMRUN to reduce jitter.
 */
#define VMCB_CLEAN_INTERCEPTS (1U << 0) /* Intercept vectors */
#define VMCB_CLEAN_IOPM (1U << 1)       /* IOPM base PA */
#define VMCB_CLEAN_MSRPM (1U << 2)      /* MSRPM base PA */
#define VMCB_CLEAN_TSC (1U << 3)        /* TSC offset */
#define VMCB_CLEAN_NP (1U << 4)         /* Nested paging (NCR3, NP enable) */
#define VMCB_CLEAN_CRX (1U << 5)        /* CR0, CR3, CR4, EFER */
#define VMCB_CLEAN_DRX (1U << 6)        /* DR6, DR7 */
#define VMCB_CLEAN_DT (1U << 7)         /* GDT, IDT */
#define VMCB_CLEAN_SEG (1U << 8)        /* CS, DS, SS, ES, CPL */
#define VMCB_CLEAN_CR2 (1U << 9)        /* CR2 */
#define VMCB_CLEAN_LBR (1U << 10)       /* LBR virt, DBGCTL */
#define VMCB_CLEAN_AVIC (1U << 11)      /* AVIC */

/* Stable fields: everything except TSC (changes per-CPU each VMRUN) */
#define VMCB_CLEAN_STABLE                                                      \
  (VMCB_CLEAN_INTERCEPTS | VMCB_CLEAN_IOPM | VMCB_CLEAN_MSRPM |                \
   VMCB_CLEAN_NP | VMCB_CLEAN_CRX | VMCB_CLEAN_DRX | VMCB_CLEAN_DT |           \
   VMCB_CLEAN_SEG | VMCB_CLEAN_CR2 | VMCB_CLEAN_LBR)

struct npt_context {
  u64 *pml4;
  phys_addr_t pml4_pa;
  struct page *pages[NPT_MAX_PAGES];
  int page_count;
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  Snapshot Sabitleri
 * ═══════════════════════════════════════════════════════════════════════════
 */

#define WATCH_NAME_MAX 64
#define SNAPSHOT_MIN_INTERVAL_SEC 1
#define PROC_DIR "svm_dump"
#define SVM_SNAPSHOT_VERSION 30

struct svm_snapshot_blob {
  void *data;
  size_t size;
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  Guest GPR State (saved/restored across VMRUN by software)
 *  VMCB hardware only saves RAX, RSP, RIP, RFLAGS.
 *  Everything else must be saved/restored in the VMRUN wrapper.
 * ═══════════════════════════════════════════════════════════════════════════
 */

struct guest_regs {
  u64 rbx;
  u64 rcx;
  u64 rdx;
  u64 rsi;
  u64 rdi;
  u64 rbp;
  u64 r8;
  u64 r9;
  u64 r10;
  u64 r11;
  u64 r12;
  u64 r13;
  u64 r14;
  u64 r15;
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  Micro-VMM IPC (Trampoline Passthrough)
 * ═══════════════════════════════════════════════════════════════════════════
 */

#define MATRIX_EXIT_REASON_NONE 0
#define MATRIX_EXIT_REASON_SYSCALL 1

struct matrix_exit_info {
  u64 exit_reason;
  u64 rax;
  u64 rdi;
  u64 rsi;
  u64 rdx;
  u64 r10;
  u64 r8;
  u64 r9;
  u64 guest_rip;
} __attribute__((aligned(64))); /* Cacheline hizali */

/* ═══════════════════════════════════════════════════════════════════════════
 *  Context Structures
 * ═══════════════════════════════════════════════════════════════════════════
 */

struct svm_context {
  struct vmcb *vmcb;
  phys_addr_t vmcb_pa;

  void *hsave_va;
  phys_addr_t hsave_pa;

  u8 *code_page;
  u8 *stack_page;

  void *msrpm_va;
  phys_addr_t msrpm_pa;

  void *iopm_va;
  phys_addr_t iopm_pa;

  struct npt_context npt;

  u64 pending_rearm_gpa;

  /* Gerekli: Kapsamdan Cikinca Yok Olmamasi İcin Guest GPR'ler */
  struct guest_regs gregs;
};

struct snap_context {
  struct mutex lock;
  struct proc_dir_entry *proc_dir;

  char watch_name[WATCH_NAME_MAX];
  struct task_struct *watcher_thread;
  bool auto_watch_active;

  bool full_dump_mode;
  bool npt_mode;

  u64 last_snapshot_time;
  int snapshot_count;

  struct svm_snapshot_blob blob;
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  Global Değişkenler (Minimum gerekli - Pointer'lar)
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* Memory API callbacks (global çünkü helper) */
typedef int (*set_memory_x_t)(unsigned long addr, int numpages);
typedef int (*set_memory_nx_t)(unsigned long addr, int numpages);
extern set_memory_x_t my_set_memory_x;
extern set_memory_nx_t my_set_memory_nx;

/* Per-CPU TSC */
DECLARE_PER_CPU(s64, pcpu_tsc_offset);

/*
 * Procfs handler'ları gibi state-pass edemediğimiz callback'ler için
 * singleton reference pointer'ları. Bunlar main.c'deki static instance'ları
 * gösterir.
 */
extern struct svm_context *g_svm;
extern struct snap_context *g_snap;

/* ═══════════════════════════════════════════════════════════════════════════
 *  Fonksiyon Prototipleri
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* svm_engine.c */
bool svm_supported(void);
int resolve_hidden_symbols(void);
void vmrun_safe(u64 vmcb_pa);
void vmrun_with_regs(u64 vmcb_pa, struct guest_regs *regs);
void raw_cr3_flush(void);

/* tsc_stealth.c */
u64 vmrun_tsc_compensated(struct svm_context *ctx);
void tsc_offset_reset(void);

/* npt_map.c */
int npt_build_identity_map(struct npt_context *ctx, u64 phys_limit);
void npt_destroy(struct npt_context *ctx);
int npt_set_page_nx(struct npt_context *ctx, u64 gpa);

/* snapshot.c */
int build_snapshot_for_task(struct snap_context *snap,
                            struct task_struct *task);
void snapshot_free_locked(struct snap_context *snap);

/* procfs_iface.c */
int procfs_init(struct snap_context *snap);
void procfs_exit(struct snap_context *snap);

/* main.c — vmcb_prepare_npt */
int vmcb_prepare_npt(struct svm_context *ctx, u64 g_rip, u64 g_rsp, u64 g_cr3);

/* vmexit.c — VMEXIT dispatch loop */
int svm_run_guest(struct svm_context *ctx, struct guest_regs *regs);

/* svm_chardev.c — Matrix IOCTL Entry Portal */
int svm_chardev_init(void);
void svm_chardev_exit(void);

/* svm_ghost.c — Ghost Injection Engine (Execve Hook) */
int svm_ghost_init(void);
void svm_ghost_exit(void);

/* Inline helpers */
static inline bool svm_check_access(void) { return capable(CAP_SYS_ADMIN); }

static inline bool svm_rate_limit_check(struct snap_context *snap) {
  u64 now = ktime_get_real_seconds();
  if (snap->last_snapshot_time &&
      (now - snap->last_snapshot_time) < SNAPSHOT_MIN_INTERVAL_SEC)
    return false;
  return true;
}

#endif /* RING_MINUS_ONE_H */
