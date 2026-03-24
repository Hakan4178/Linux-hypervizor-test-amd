/*
 * procfs_iface.c — /proc/svm_dump Interface
 *
 * Proc handlers: target_pid, output, process_list, watch_name,
 * auto_watch, full_dump, npt_mode, status.
 */

#include "ring_minus_one.h"

/* ═══════════════════════════════════════════════════════════════════════════
 *  Watcher Thread
 * ═══════════════════════════════════════════════════════════════════════════ */

static int watcher_fn(void *data)
{
    struct snap_context *snap = (struct snap_context *)data;
    while (!kthread_should_stop()) {
        struct task_struct *task;
        struct task_struct *target_task = NULL;
        char local_name[WATCH_NAME_MAX];

        mutex_lock(&snap->lock);
        memcpy(local_name, snap->watch_name, sizeof(local_name));
        mutex_unlock(&snap->lock);

        if (local_name[0] == 0) {
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(msecs_to_jiffies(500));
            continue;
        }

        rcu_read_lock();
        for_each_process(task) {
            if (strncmp(task->comm, local_name, TASK_COMM_LEN) == 0) {
                get_task_struct(task);
                target_task = task;
                break;
            }
        }
        rcu_read_unlock();

        if (target_task) {
            u64 now = ktime_get_real_seconds();
            if (!snap->last_snapshot_time || (now - snap->last_snapshot_time) >= SNAPSHOT_MIN_INTERVAL_SEC) {
                mutex_lock(&snap->lock);
                pr_notice("[SVM_DUMP] AUDIT: action=auto pid=%d by=%s\n",
                         task_pid_nr(target_task), current->comm);
                build_snapshot_for_task(snap, target_task);
                mutex_unlock(&snap->lock);
            }
            put_task_struct(target_task);
        }

        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(msecs_to_jiffies(500));
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Proc Handlers
 * ═══════════════════════════════════════════════════════════════════════════ */

static ssize_t pid_write(struct file *f, const char __user *u, size_t c, loff_t *p)
{
    char buf[16];
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

    mutex_lock(&g_snap->lock);
    pr_notice("[SVM_DUMP] AUDIT: action=manual pid=%d by=%s\n", val, current->comm);
    build_snapshot_for_task(g_snap, t);
    mutex_unlock(&g_snap->lock);

    put_task_struct(t);
    put_pid(ps);

    return c;
}

static ssize_t out_read(struct file *f, char __user *u, size_t c, loff_t *p)
{
    ssize_t r;

    mutex_lock(&g_snap->lock);
    if (!g_snap->blob.data) {
        mutex_unlock(&g_snap->lock);
        return -ENOENT;
    }
    r = simple_read_from_buffer(u, c, p, g_snap->blob.data, g_snap->blob.size);
    mutex_unlock(&g_snap->lock);

    return r;
}

static int pl_show(struct seq_file *m, void *v)
{
    struct task_struct *task;

    seq_printf(m, "%-8s %-20s\n", "PID", "NAME");
    rcu_read_lock();
    for_each_process(task) {
        seq_printf(m, "%-8d %-20s\n", task_pid_nr(task), task->comm);
    }
    rcu_read_unlock();

    return 0;
}

static int pl_open(struct inode *i, struct file *f)
{
    return single_open(f, pl_show, NULL);
}

static ssize_t wn_write(struct file *f, const char __user *u, size_t c, loff_t *p)
{
    if (!svm_check_access())
        return -EPERM;

    mutex_lock(&g_snap->lock);
    memset(g_snap->watch_name, 0, sizeof(g_snap->watch_name));
    if (copy_from_user(g_snap->watch_name, u, min(c, (size_t)63))) {
        memset(g_snap->watch_name, 0, sizeof(g_snap->watch_name));
        mutex_unlock(&g_snap->lock);
        return -EFAULT;
    }
    g_snap->watch_name[min(c, (size_t)63)] = 0;
    strim(g_snap->watch_name);
    mutex_unlock(&g_snap->lock);

    return c;
}

static ssize_t aw_write(struct file *f, const char __user *u, size_t c, loff_t *p)
{
    char buf[8];
    int v;

    if (!svm_check_access())
        return -EPERM;

    if (copy_from_user(buf, u, min(c, sizeof(buf) - 1)))
        return -EFAULT;
    buf[min(c, sizeof(buf) - 1)] = 0;

    if (kstrtoint(strim(buf), 10, &v))
        return -EINVAL;

    mutex_lock(&g_snap->lock);
    if (v == 1 && !g_snap->auto_watch_active) {
        struct task_struct *t = kthread_run(watcher_fn, g_snap, "svm_watch");
        if (!IS_ERR(t)) {
            g_snap->watcher_thread = t;
            g_snap->auto_watch_active = true;
        }
    } else if (v == 0 && g_snap->auto_watch_active) {
        struct task_struct *t = g_snap->watcher_thread;
        g_snap->watcher_thread = NULL;
        g_snap->auto_watch_active = false;
        mutex_unlock(&g_snap->lock);
        kthread_stop(t);
        return c;
    }
    mutex_unlock(&g_snap->lock);

    return c;
}

static ssize_t fd_write(struct file *f, const char __user *u, size_t c, loff_t *p)
{
    char buf[8];
    int v;

    if (!svm_check_access())
        return -EPERM;

    if (copy_from_user(buf, u, min(c, sizeof(buf) - 1)))
        return -EFAULT;
    buf[min(c, sizeof(buf) - 1)] = 0;

    if (kstrtoint(strim(buf), 10, &v))
        return -EINVAL;

    mutex_lock(&g_snap->lock);
    g_snap->full_dump_mode = (v == 1);
    mutex_unlock(&g_snap->lock);

    return c;
}

static ssize_t nm_write(struct file *f, const char __user *u, size_t c, loff_t *p)
{
    char buf[8];
    int v;

    if (!svm_check_access())
        return -EPERM;

    if (copy_from_user(buf, u, min(c, sizeof(buf) - 1)))
        return -EFAULT;
    buf[min(c, sizeof(buf) - 1)] = 0;

    if (kstrtoint(strim(buf), 10, &v))
        return -EINVAL;

    mutex_lock(&g_snap->lock);
    g_snap->npt_mode = (v == 1);
    mutex_unlock(&g_snap->lock);

    return c;
}

static int st_show(struct seq_file *m, void *v)
{
    mutex_lock(&g_snap->lock);
    seq_printf(m, "Watch: %s\n", g_snap->watch_name);
    seq_printf(m, "Full: %s\n", g_snap->full_dump_mode ? "ON" : "OFF");
    seq_printf(m, "NPT: %s\n", g_snap->npt_mode ? "ON" : "OFF");
    seq_printf(m, "Size: %zu\n", g_snap->blob.size);
    seq_printf(m, "Ready: %s\n", g_snap->blob.data ? "YES" : "NO");
    mutex_unlock(&g_snap->lock);

    return 0;
}

static int st_open(struct inode *i, struct file *f)
{
    return single_open(f, st_show, NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Proc Ops Yapıları
 * ═══════════════════════════════════════════════════════════════════════════ */

static const struct proc_ops pops_p = { .proc_write = pid_write };
static const struct proc_ops pops_o = { .proc_read  = out_read };
static const struct proc_ops pops_l = {
    .proc_open = pl_open, .proc_read = seq_read,
    .proc_lseek = seq_lseek, .proc_release = single_release
};
static const struct proc_ops pops_w = { .proc_write = wn_write };
static const struct proc_ops pops_a = { .proc_write = aw_write };
static const struct proc_ops pops_f = { .proc_write = fd_write };
static const struct proc_ops pops_n = { .proc_write = nm_write };
static const struct proc_ops pops_s = {
    .proc_open = st_open, .proc_read = seq_read,
    .proc_lseek = seq_lseek, .proc_release = single_release
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  Procfs Init / Exit
 * ═══════════════════════════════════════════════════════════════════════════ */

int procfs_init(struct snap_context *snap)
{
    snap->proc_dir = proc_mkdir(PROC_DIR, NULL);
    if (!snap->proc_dir)
        return -ENOMEM;

    if (!proc_create("target_pid", 0600, snap->proc_dir, &pops_p) ||
        !proc_create("output", 0400, snap->proc_dir, &pops_o) ||
        !proc_create("process_list", 0400, snap->proc_dir, &pops_l) ||
        !proc_create("watch_name", 0600, snap->proc_dir, &pops_w) ||
        !proc_create("auto_watch", 0600, snap->proc_dir, &pops_a) ||
        !proc_create("full_dump", 0600, snap->proc_dir, &pops_f) ||
        !proc_create("npt_mode", 0600, snap->proc_dir, &pops_n) ||
        !proc_create("status", 0400, snap->proc_dir, &pops_s)) {

        remove_proc_subtree(PROC_DIR, NULL);
        return -ENOMEM;
    }

    return 0;
}

void procfs_exit(struct snap_context *snap)
{
    struct task_struct *t = NULL;

    mutex_lock(&snap->lock);
    if (snap->auto_watch_active) {
        t = snap->watcher_thread;
        snap->watcher_thread = NULL;
        snap->auto_watch_active = false;
    }
    snapshot_free_locked(snap);
    mutex_unlock(&snap->lock);

    if (t)
        kthread_stop(t);

    remove_proc_subtree(PROC_DIR, NULL);
}
