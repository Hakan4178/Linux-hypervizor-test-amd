#include <asm/pgtable.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
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

/* Forward declaration — full definition in ring_minus_one.h */
struct snap_context;
int procfs_init(struct snap_context *snap);
void procfs_exit(struct snap_context *snap);
#include <asm/page.h>
#include <asm/svm.h>
#include <linux/io.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  NPT (Nested Page Table) — Tanımlar & Yapılar
 *  AMD64 4-level NPT identity map (GPA == HPA) with 2MB leaf entries.
 *  Eskiden npt_walk.h / npt_walk.c olarak ayrı modüldü, artık svm_dump'a
 *  entegre edildi.
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* NPT page table entry flags (AMD64 long mode) */
#define NPT_PRESENT (1ULL << 0)
#define NPT_WRITE (1ULL << 1)
#define NPT_USER (1ULL << 2)
#define NPT_PS (1ULL << 7) /* Page Size: 2MB in PD, 1GB in PDPT */
#define NPT_NX (1ULL << 63)

#define NPT_DEFAULT_FLAGS (NPT_PRESENT | NPT_WRITE | NPT_USER)
#define NPT_MAX_PAGES 8192 /* max pages for NPT structures */

/* NPT PAT/Cache type bits for 2MB pages (AMD64 APM Vol.2 Table 5-6) */
#define NPT_PWT (1ULL << 3)
#define NPT_PCD (1ULL << 4)
#define NPT_PAT_LARGE (1ULL << 12)
#define NPT_CACHE_WB 0ULL
#define NPT_CACHE_UC (NPT_PWT | NPT_PCD)

struct npt_context {
  u64 *pml4;
  phys_addr_t pml4_pa;
  struct page *pages[NPT_MAX_PAGES];
  int page_count;
};

/* MODULE_* macros live in main.c; this file is a TU within ring_minus_one.ko */

#define WATCH_NAME_MAX 64
#define SNAPSHOT_MIN_INTERVAL_SEC 1
#define PROC_DIR "svm_dump"
#define SVM_SNAPSHOT_VERSION 30

static struct proc_dir_entry *proc_dir;
static DEFINE_MUTEX(snapshot_lock);

static char watch_name[WATCH_NAME_MAX];
static struct task_struct *watcher_thread;
static bool auto_watch_active;
static int snapshot_count;
static u64 last_snapshot_time;
static bool full_dump_mode = false;
static bool npt_mode = false;

/* External symbols from ring_minus_one module */
extern u64 vmrun_tsc_compensated(struct vmcb *vmcb, u64 vmcb_pa);
extern int vmcb_prepare_npt(struct vmcb *vmcb, u64 g_rip, u64 g_rsp, u64 g_cr3,
                            struct npt_context *npt);
extern void tsc_offset_reset(void);

struct svm_snapshot_blob {
  void *data;
  size_t size;
};

static struct svm_snapshot_blob snapshot_blob = {NULL, 0};

static inline bool svm_check_access(void) { return capable(CAP_SYS_ADMIN); }

/* NPT functions implemented and exported by npt_walk.c. */
extern int npt_build_identity_map(struct npt_context *ctx, u64 phys_limit);
extern void npt_destroy(struct npt_context *ctx);

/* ═══════════════════════════════════════════════════════════════════════════
 *  SNAPSHOT — Yardımcı Fonksiyonlar
 * ═══════════════════════════════════════════════════════════════════════════
 */

static inline bool svm_rate_limit_check(void) {
  u64 now = ktime_get_real_seconds();
  if (last_snapshot_time &&
      (now - last_snapshot_time) < SNAPSHOT_MIN_INTERVAL_SEC)
    return false;
  return true;
}

static void svm_audit_log(const char *action, int pid_val) {
  pr_notice("[SVM_DUMP] AUDIT: action=%s pid=%d by=%s\n", action, pid_val,
            current->comm);
}

static u64 compute_checksum(const void *data, size_t len) {
  const u64 *ptr = data;
  u64 cksum = 0x5356444D48414B41ULL;
  size_t i, words = len / sizeof(u64);

  for (i = 0; i < words; i++)
    cksum ^= ptr[i];
  return cksum & 0xFFFFFFFFFFFFFFFFULL;
}

static void snapshot_free_locked(void) {
  if (snapshot_blob.data) {
    kvfree(snapshot_blob.data);
    snapshot_blob.data = NULL;
    snapshot_blob.size = 0;
  }
}

static void count_snapshot_entries(struct mm_struct *mm, u64 *vma_count,
                                   u64 *map_count, u64 *data_size) {
  struct vm_area_struct *vma;
  unsigned long addr;

  VMA_ITERATOR(vmi, mm, 0);
  *vma_count = 0;
  *map_count = 0;
  *data_size = 0;

  mmap_read_lock(mm);
  for_each_vma(vmi, vma) {
    (*vma_count)++;
    for (addr = vma->vm_start; addr < vma->vm_end;) {
      pgd_t *pgd = pgd_offset(mm, addr);
      p4d_t *p4d;
      pud_t *pud;
      pmd_t *pmd;

      if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        addr = (addr & PGDIR_MASK) + PGDIR_SIZE;
        continue;
      }
      p4d = p4d_offset(pgd, addr);
      if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        addr = (addr & P4D_MASK) + P4D_SIZE;
        continue;
      }
      pud = pud_offset(p4d, addr);
      if (pud_none(*pud) || pud_bad(*pud)) {
        addr = (addr & PUD_MASK) + PUD_SIZE;
        continue;
      }
      if (pud_leaf(*pud)) {
        unsigned long next = (addr & PUD_MASK) + PUD_SIZE;
        if (next > vma->vm_end || next < addr)
          next = vma->vm_end;
        (*map_count)++;
        *data_size += (next - addr);
        addr = next;
        continue;
      }
      pmd = pmd_offset(pud, addr);
      if (pmd_none(*pmd) || pmd_bad(*pmd) || !pmd_present(*pmd)) {
        addr = (addr & PMD_MASK) + PMD_SIZE;
        continue;
      }
      if (pmd_leaf(*pmd)) {
        unsigned long next = (addr & PMD_MASK) + PMD_SIZE;
        if (next > vma->vm_end || next < addr)
          next = vma->vm_end;
        (*map_count)++;
        *data_size += (next - addr);
        addr = next;
        continue;
      }
      (*map_count)++;
      *data_size += PAGE_SIZE;
      addr += PAGE_SIZE;
    }
  }
  mmap_read_unlock(mm);
}

static int build_snapshot_for_task(struct task_struct *task) {
  struct mm_struct *mm;
  struct svm_dump_header *hdr;
  struct svm_vma_entry *vma_out;
  struct svm_page_map_entry *map_out;
  void *buf;
  size_t meta_size, data_size_est, total_alloc;
  u64 v_cnt = 0, m_cnt = 0, i_vma = 0, i_map = 0, raw_off = 0,
      total_data_sz = 0;
  struct vm_area_struct *vma;
  unsigned long addr;
  u8 *raw_buf = NULL;

  mm = get_task_mm(task);
  if (!mm)
    return -EINVAL;

  count_snapshot_entries(mm, &v_cnt, &m_cnt, &total_data_sz);

  meta_size =
      sizeof(*hdr) + v_cnt * sizeof(*vma_out) + m_cnt * sizeof(*map_out);
  data_size_est = full_dump_mode ? total_data_sz : 0;
  total_alloc = meta_size + data_size_est + 4096;

  buf = kvzalloc(total_alloc, GFP_KERNEL);
  if (!buf) {
    mmput(mm);
    return -ENOMEM;
  }

  hdr = buf;
  vma_out = (void *)(hdr + 1);
  map_out = (void *)(vma_out + v_cnt);

  if (full_dump_mode)
    raw_buf = (u8 *)(map_out + m_cnt);

  mmap_read_lock(mm);

  VMA_ITERATOR(vmi, mm, 0);
  for_each_vma(vmi, vma) {
    if (i_vma >= v_cnt)
      break;
    vma_out[i_vma].vma_start = vma->vm_start;
    vma_out[i_vma].vma_end = vma->vm_end;
    vma_out[i_vma].flags = vma->vm_flags;
    vma_out[i_vma].pgoff = vma->vm_pgoff;
    i_vma++;
  }

  VMA_ITERATOR(vmi2, mm, 0);
  for_each_vma(vmi2, vma) {
    for (addr = vma->vm_start; addr < vma->vm_end;) {
      pgd_t *pgd;
      p4d_t *p4d;
      pud_t *pud;
      pmd_t *pmd;
      unsigned long pfn_val = 0, pg_size = 0;
      u64 pg_ent = 0;
      int pg_k = 0;

      if (i_map >= m_cnt)
        goto out_unl; /* Prevent TOCTOU array overflow */

      pgd = pgd_offset(mm, addr);
      if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        addr = (addr & PGDIR_MASK) + PGDIR_SIZE;
        continue;
      }
      p4d = p4d_offset(pgd, addr);
      if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        addr = (addr & P4D_MASK) + P4D_SIZE;
        continue;
      }
      pud = pud_offset(p4d, addr);
      if (pud_none(*pud) || pud_bad(*pud)) {
        addr = (addr & PUD_MASK) + PUD_SIZE;
        continue;
      }
      if (pud_leaf(*pud)) {
        pfn_val = pud_pfn(*pud);
        pg_size = PUD_SIZE;
        pg_ent = pud_val(*pud);
        pg_k = 3;
        goto fill;
      }
      pmd = pmd_offset(pud, addr);
      if (pmd_none(*pmd) || pmd_bad(*pmd) || !pmd_present(*pmd)) {
        addr = (addr & PMD_MASK) + PMD_SIZE;
        continue;
      }
      if (pmd_leaf(*pmd)) {
        pfn_val = pmd_pfn(*pmd);
        pg_size = PMD_SIZE;
        pg_ent = pmd_val(*pmd);
        pg_k = 2;
        goto fill;
      }
      {
        pte_t *pbase;
        /*
         * Z1 FIX: Validate pmd_page_vaddr result.
         * A corrupted PMD could yield a NULL or invalid pointer.
         */
        if (!pmd_present(*pmd))
          goto skip_pte;
        pbase = (pte_t *)pmd_page_vaddr(*pmd);
        if (!pbase)
          goto skip_pte;
        if (pte_present(*(pbase + pte_index(addr)))) {
          pfn_val = pte_pfn(*(pbase + pte_index(addr)));
          pg_size = PAGE_SIZE;
          pg_ent = pte_val(*(pbase + pte_index(addr)));
          pg_k = 1;
          goto fill;
        }
      }
    skip_pte:
      addr += PAGE_SIZE;
      continue;

    fill: {
      unsigned long mask =
          (pg_k == 3) ? PUD_MASK : ((pg_k == 2) ? PMD_MASK : PAGE_MASK);
      unsigned long page_start_vaddr = addr & mask;
      unsigned long next = page_start_vaddr + pg_size;
      if (next > vma->vm_end || next < addr)
        next = vma->vm_end;

      unsigned long chunk_size = next - addr;
      unsigned long offset_in_page = addr - page_start_vaddr;

      map_out[i_map].addr = addr;
      map_out[i_map].size = chunk_size;
      map_out[i_map].entry = pg_ent;
      map_out[i_map].pfn = pfn_val;
      map_out[i_map].kind = pg_k;

      if (full_dump_mode && raw_buf && pfn_valid(pfn_val)) {
        struct page *pg = pfn_to_page(pfn_val);
        /*
         * Swap safety: Only copy if the page is
         * genuinely in RAM (not swapped, not reserved I/O).
         * page_count == 0 means it's free/unused.
         * PageReserved means it's MMIO or firmware.
         */
        if (pg && page_count(pg) > 0 && !PageReserved(pg)) {
          void *vsrc = pfn_to_kaddr(pfn_val);
          /*
           * Z2 FIX: Bounds check before memcpy.
           * Prevent TOCTOU buffer overflow if VMAs changed
           * between count and build phases.
           */
          if (vsrc && (raw_off + chunk_size) <= data_size_est) {
            memcpy(raw_buf + raw_off, (u8 *)vsrc + offset_in_page, chunk_size);
            map_out[i_map].data_offset = raw_off;
            raw_off += chunk_size;
          } else {
            map_out[i_map].data_offset = (u64)-1;
          }
        } else {
          map_out[i_map].data_offset = (u64)-1;
        }
      } else {
        map_out[i_map].data_offset = (u64)-1;
      }

      i_map++;
      addr = next;
    }
    }
  }

out_unl:
  mmap_read_unlock(mm);

  memcpy(hdr->magic, SVM_MAGIC, 4);
  hdr->version = SVM_SNAPSHOT_VERSION;
  hdr->pid = task_pid_nr(task);
  hdr->timestamp = ktime_get_real_seconds();
  hdr->cr3_phys = __pa(mm->pgd);
  hdr->vma_count = i_vma;
  hdr->map_count = i_map;
  hdr->total_size = (u8 *)(map_out + i_map) - (u8 *)buf;

  if (full_dump_mode) {
    hdr->flags |= SVM_FLAG_RAW_DATA;
    hdr->total_size += raw_off;
  }
  if (npt_mode)
    hdr->flags |= SVM_FLAG_NPT_MODE;

  /*
   * Z3 FIX: If total_size exceeds allocation, cap it and
   * set TRUNCATED flag so the analyst knows the checksum
   * covers only partial data.
   */
  if (hdr->total_size > total_alloc) {
    pr_warn("[SVM_DUMP] TRUNCATED: total_size %llu > alloc %zu, capping\n",
            hdr->total_size, total_alloc);
    hdr->total_size = total_alloc;
    hdr->flags |= SVM_FLAG_TRUNCATED;
  }

  hdr->checksum = 0;
  hdr->checksum = compute_checksum(buf, (size_t)hdr->total_size);

  mmput(mm);

  /* Assume snapshot_lock is held by caller where necessary */
  snapshot_free_locked();
  snapshot_blob.data = buf;
  snapshot_blob.size = (size_t)hdr->total_size;
  last_snapshot_time = ktime_get_real_seconds();
  snapshot_count++;

  return 0;
}

static int watcher_fn(void *data) {
  while (!kthread_should_stop()) {
    struct task_struct *task;
    struct task_struct *target_task = NULL;

    if (watch_name[0] == 0) {
      set_current_state(TASK_INTERRUPTIBLE);
      schedule_timeout(msecs_to_jiffies(500));
      continue;
    }

    rcu_read_lock();
    for_each_process(task) {
      if (strncmp(task->comm, watch_name, TASK_COMM_LEN) == 0) {
        get_task_struct(task);
        target_task = task;
        break;
      }
    }
    rcu_read_unlock();

    if (target_task) {
      u64 now = ktime_get_real_seconds();
      if (!last_snapshot_time ||
          (now - last_snapshot_time) >= SNAPSHOT_MIN_INTERVAL_SEC) {
        mutex_lock(&snapshot_lock);
        svm_audit_log("auto", task_pid_nr(target_task));
        build_snapshot_for_task(target_task);
        mutex_unlock(&snapshot_lock);
      }
      put_task_struct(target_task);
    }

    set_current_state(TASK_INTERRUPTIBLE);
    schedule_timeout(msecs_to_jiffies(500));
  }
  return 0;
}

static ssize_t pid_write(struct file *f, const char __user *u, size_t c,
                         loff_t *p) {
  char buf[16] = {0};
  int val;
  struct pid *ps;
  struct task_struct *t;

  if (!svm_check_access())
    return -EPERM;

  if (copy_from_user(buf, u, min(c, sizeof(buf) - 1)))
    return -EFAULT;
  buf[min(c, sizeof(buf) - 1)] = 0;

  if (kstrtoint(strim(buf), 10, &val))
    return -EINVAL;

  ps = find_get_pid(val);
  if (!ps)
    return -ESRCH;

  t = get_pid_task(ps, PIDTYPE_PID);
  if (!t) {
    put_pid(ps);
    return -ESRCH;
  }

  mutex_lock(&snapshot_lock);
  svm_audit_log("manual", val);
  build_snapshot_for_task(t);
  mutex_unlock(&snapshot_lock);

  put_task_struct(t);
  put_pid(ps);

  return c;
}

static ssize_t out_read(struct file *f, char __user *u, size_t c, loff_t *p) {
  ssize_t r;

  mutex_lock(&snapshot_lock);
  if (!snapshot_blob.data) {
    mutex_unlock(&snapshot_lock);
    return -ENOENT;
  }
  r = simple_read_from_buffer(u, c, p, snapshot_blob.data, snapshot_blob.size);
  mutex_unlock(&snapshot_lock);

  return r;
}

static int pl_show(struct seq_file *m, void *v) {
  struct task_struct *task;

  seq_printf(m, "%-8s %-20s\n", "PID", "NAME");
  rcu_read_lock();
  for_each_process(task) {
    seq_printf(m, "%-8d %-20s\n", task_pid_nr(task), task->comm);
  }
  rcu_read_unlock();

  return 0;
}

static int pl_open(struct inode *i, struct file *f) {
  return single_open(f, pl_show, NULL);
}

static ssize_t wn_write(struct file *f, const char __user *u, size_t c,
                        loff_t *p) {
  if (!svm_check_access())
    return -EPERM;

  mutex_lock(&snapshot_lock);
  /*
   * Z4 FIX: Zero entire buffer before copy to prevent
   * leaking old watch_name contents through /proc/svm_dump/status.
   */
  memset(watch_name, 0, sizeof(watch_name));
  if (copy_from_user(watch_name, u, min(c, (size_t)63))) {
    memset(watch_name, 0, sizeof(watch_name));
    mutex_unlock(&snapshot_lock);
    return -EFAULT;
  }
  watch_name[min(c, (size_t)63)] = 0;
  strim(watch_name);
  mutex_unlock(&snapshot_lock);

  return c;
}

static ssize_t aw_write(struct file *f, const char __user *u, size_t c,
                        loff_t *p) {
  char buf[8] = {0};
  int v;

  if (!svm_check_access())
    return -EPERM;

  if (copy_from_user(buf, u, min(c, sizeof(buf) - 1)))
    return -EFAULT;
  buf[min(c, sizeof(buf) - 1)] = 0;

  if (kstrtoint(strim(buf), 10, &v))
    return -EINVAL;

  mutex_lock(&snapshot_lock);
  if (v == 1 && !auto_watch_active) {
    struct task_struct *t = kthread_run(watcher_fn, NULL, "svm_watch");
    if (!IS_ERR(t)) {
      watcher_thread = t;
      auto_watch_active = true;
    }
  } else if (v == 0 && auto_watch_active) {
    struct task_struct *t = watcher_thread;
    watcher_thread = NULL;
    auto_watch_active = false;
    mutex_unlock(&snapshot_lock);

    /* Stop the thread outside the lock to prevent deadlock */
    kthread_stop(t);
    return c;
  }
  mutex_unlock(&snapshot_lock);

  return c;
}

static ssize_t fd_write(struct file *f, const char __user *u, size_t c,
                        loff_t *p) {
  char buf[8];
  int v;

  if (!svm_check_access())
    return -EPERM;

  if (copy_from_user(buf, u, min(c, sizeof(buf) - 1)))
    return -EFAULT;
  buf[min(c, sizeof(buf) - 1)] = 0;

  if (kstrtoint(strim(buf), 10, &v))
    return -EINVAL;

  mutex_lock(&snapshot_lock);
  full_dump_mode = (v == 1);
  mutex_unlock(&snapshot_lock);

  return c;
}

static ssize_t nm_write(struct file *f, const char __user *u, size_t c,
                        loff_t *p) {
  char buf[8];
  int v;

  if (!svm_check_access())
    return -EPERM;

  if (copy_from_user(buf, u, min(c, sizeof(buf) - 1)))
    return -EFAULT;
  buf[min(c, sizeof(buf) - 1)] = 0;

  if (kstrtoint(strim(buf), 10, &v))
    return -EINVAL;

  mutex_lock(&snapshot_lock);
  npt_mode = (v == 1);
  mutex_unlock(&snapshot_lock);

  return c;
}

static int st_show(struct seq_file *m, void *v) {
  mutex_lock(&snapshot_lock);
  seq_printf(m, "Watch: %s\n", watch_name);
  seq_printf(m, "Full: %s\n", full_dump_mode ? "ON" : "OFF");
  seq_printf(m, "NPT: %s\n", npt_mode ? "ON" : "OFF");
  seq_printf(m, "Size: %zu\n", snapshot_blob.size);
  seq_printf(m, "Ready: %s\n", snapshot_blob.data ? "YES" : "NO");
  mutex_unlock(&snapshot_lock);

  return 0;
}

static int st_open(struct inode *i, struct file *f) {
  return single_open(f, st_show, NULL);
}

static const struct proc_ops pops_p = {.proc_write = pid_write};

static const struct proc_ops pops_o = {.proc_read = out_read};

static const struct proc_ops pops_l = {.proc_open = pl_open,
                                       .proc_read = seq_read,
                                       .proc_lseek = seq_lseek,
                                       .proc_release = single_release};

static const struct proc_ops pops_w = {.proc_write = wn_write};

static const struct proc_ops pops_a = {.proc_write = aw_write};

static const struct proc_ops pops_f = {.proc_write = fd_write};

static const struct proc_ops pops_n = {.proc_write = nm_write};

static const struct proc_ops pops_s = {.proc_open = st_open,
                                       .proc_read = seq_read,
                                       .proc_lseek = seq_lseek,
                                       .proc_release = single_release};

int procfs_init(struct snap_context *snap) {
  (void)snap; /* snap_context handled externally; we use module globals */

  proc_dir = proc_mkdir(PROC_DIR, NULL);
  if (!proc_dir)
    return -ENOMEM;

  if (!proc_create("target_pid", 0600, proc_dir, &pops_p) ||
      !proc_create("output", 0400, proc_dir, &pops_o) ||
      !proc_create("process_list", 0400, proc_dir, &pops_l) ||
      !proc_create("watch_name", 0600, proc_dir, &pops_w) ||
      !proc_create("auto_watch", 0600, proc_dir, &pops_a) ||
      !proc_create("full_dump", 0600, proc_dir, &pops_f) ||
      !proc_create("npt_mode", 0600, proc_dir, &pops_n) ||
      !proc_create("status", 0400, proc_dir, &pops_s)) {
    remove_proc_subtree(PROC_DIR, NULL);
    return -ENOMEM;
  }

  return 0;
}

void procfs_exit(struct snap_context *snap) {
  struct task_struct *t = NULL;

  (void)snap;

  mutex_lock(&snapshot_lock);
  if (auto_watch_active) {
    t = watcher_thread;
    watcher_thread = NULL;
    auto_watch_active = false;
  }
  snapshot_free_locked();
  mutex_unlock(&snapshot_lock);

  if (t)
    kthread_stop(t);

  remove_proc_subtree(PROC_DIR, NULL);
}
