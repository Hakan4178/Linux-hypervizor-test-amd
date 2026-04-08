// SPDX-License-Identifier: GPL-2.0-only

#include "ring_minus_one.h"
#include "svm_trace.h"
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  Watchlist — Cerrahi Hedef Listesi
 *  Maksimum 64 bölge izlenebilir. Her bölge bir GPA aralığıdır.
 *  Aralık, 2MB sınırlarına hizalanır (NPT PD seviyesi).
 * ═══════════════════════════════════════════════════════════════════════════
 */

#define NPT_HOOK_MAX_WATCHES 64

struct npt_watch_entry {
	u64 gpa_start; /* 2MB-aligned başlangıç GPA */
	u64 gpa_end;   /* 2MB-aligned bitiş GPA (exclusive) */
	u32 flags;     /* NPT_WATCH_NX | NPT_WATCH_RO */
	bool active;
};

#define NPT_WATCH_NX (1U << 0) /* Execute trap (VMP decrypt izleme) */
#define NPT_WATCH_RO (1U << 1) /* Write trap (Dirty page izleme) */

static struct npt_watch_entry watch_table[NPT_HOOK_MAX_WATCHES];
static int watch_count;
static DEFINE_SPINLOCK(watch_lock);

/* ── Procfs entry ── */
static struct proc_dir_entry *hook_proc_entry;

/* ═══════════════════════════════════════════════════════════════════════════
 *  Watchlist API — Kernel-internal
 * ═══════════════════════════════════════════════════════════════════════════
 */

/* Phase 26: 2MB Bitmap representing up to 64GB of Guest Physical Memory. 1 bit = 4KB page Watch
 * status */
u64 hook_bitmap[262144] __aligned(64);
EXPORT_SYMBOL_GPL(hook_bitmap);

/*
 * Securely translate a Guest Physical Address (GPA) to a Host Physical
 * Address (HPA) by walking the NPT map.
 */
u64 npt_get_hpa(struct npt_context *ctx, u64 gpa)
{
	u64 *pml4 = ctx->pml4;
	int pml4i = (gpa >> 39) & 0x1FF;
	int pdpti = (gpa >> 30) & 0x1FF;
	int pdi = (gpa >> 21) & 0x1FF;
	u64 pdpt_phys, *pdpt, pd_phys, *pd, pde, hpa_base;

	if (!pml4)
		return 0;

	/* 1. PML4 -> PDPT */
	if (!(pml4[pml4i] & 1))
		return 0;				 /* Present bit check */
	pdpt_phys = pml4[pml4i] & 0x000FFFFFFFFFF000ULL; /* NX (bit 63) ve reserved bit mask */
	if (!pdpt_phys || !pfn_valid(pdpt_phys >> PAGE_SHIFT))
		return 0;
	pdpt = (u64 *)phys_to_virt(pdpt_phys); /* Pointer cast aritmetiği koruması */

	/* 2. PDPT -> PD */
	if (!(pdpt[pdpti] & 1))
		return 0;
	pd_phys = pdpt[pdpti] & 0x000FFFFFFFFFF000ULL;
	if (!pd_phys || !pfn_valid(pd_phys >> PAGE_SHIFT))
		return 0;
	pd = (u64 *)phys_to_virt(pd_phys);

	/* 3. PD -> PTE veya 2MB Page */
	pde = pd[pdi];
	if (!(pde & 1))
		return 0; /* Present bit = 0 (sayfa NPT'de yok) */

	/* Active SVM Identity Map currently uses exclusively 2MB pages */
	if (pde & (1ULL << 7)) { /* PSE (Page Size Extension) for 2MB pages */
		hpa_base = pde & 0x000FFFFFFFFE0000ULL;	      /* 2MB base mask (Bits 51:21) */
		return hpa_base | (gpa & ((2ULL << 20) - 1)); /* Kalan 21 bit offset */
	} else {
		/* Fallback for 4KB pages in case the identity map gets rebuilt with them */
		int pti = (gpa >> 12) & 0x1FF;
		u64 pt_phys = pde & 0x000FFFFFFFFFF000ULL;
		u64 *pt, pte;

		if (!pt_phys || !pfn_valid(pt_phys >> PAGE_SHIFT))
			return 0;
		pt = (u64 *)phys_to_virt(pt_phys);
		pte = pt[pti];
		if (!(pte & 1))
			return 0;
		return (pte & 0x000FFFFFFFFFF000ULL) | (gpa & 0xFFF); /* 4KB offset */
	}
}

/*
 * npt_hook_add_watch - Belirtilen GPA aralığını izleme listesine ekle
 * @ctx: NPT context (sayfa tablosu değişiklikleri için)
 * @gpa_start: İzlenecek bölgenin başlangıç adresi
 * @gpa_end: İzlenecek bölgenin bitiş adresi (exclusive)
 * @flags: NPT_WATCH_NX ve/veya NPT_WATCH_RO
 *
 * Returns: 0 on success, -ENOSPC if table full, -EINVAL if bad params
 */
int npt_hook_add_watch(struct npt_context *ctx, u64 gpa_start, u64 gpa_end, u32 flags)
{
	unsigned long irqflags;
	int i, slot = -1;
	u64 gpa;

	if (!ctx || !ctx->pml4 || gpa_start >= gpa_end)
		return -EINVAL;

	/* 2MB hizalama */
	gpa_start &= ~((2ULL << 20) - 1);
	gpa_end = ALIGN(gpa_end, 2ULL << 20);

	spin_lock_irqsave(&watch_lock, irqflags);

	/* Duplicate kontrolü */
	for (i = 0; i < NPT_HOOK_MAX_WATCHES; i++) {
		if (watch_table[i].active && watch_table[i].gpa_start == gpa_start &&
		    watch_table[i].gpa_end == gpa_end) {
			spin_unlock_irqrestore(&watch_lock, irqflags);
			return 0; /* Zaten izleniyor */
		}
		if (!watch_table[i].active && slot < 0)
			slot = i;
	}

	if (slot < 0) {
		spin_unlock_irqrestore(&watch_lock, irqflags);
		return -ENOSPC;
	}

	watch_table[slot].gpa_start = gpa_start;
	watch_table[slot].gpa_end = gpa_end;
	watch_table[slot].flags = flags;
	watch_table[slot].active = true;
	watch_count++;

	spin_unlock_irqrestore(&watch_lock, irqflags);

	/* NPT sayfalarını işaretle ve Phase 26 JMP Bitmap'i güncelle */
	for (gpa = gpa_start; gpa < gpa_end; gpa += (2ULL << 20)) {
		if (flags & NPT_WATCH_NX)
			npt_set_page_nx(ctx, gpa);
		if (flags & NPT_WATCH_RO)
			npt_set_page_ro(ctx, gpa);

		{
			u64 p;
			for (p = 0; p < 512; p++)
				__set_bit((gpa >> 12) + p, (unsigned long *)hook_bitmap);
		}
	}

	pr_info("[ACPI_DAEMON] Watch added: GPA 0x%llx-0x%llx flags=0x%x\n", gpa_start, gpa_end,
		flags);
	return 0;
}

/*
 * npt_hook_remove_watch - İzleme listesinden kaldır ve NPT'yi geri al
 */
int npt_hook_remove_watch(struct npt_context *ctx, u64 gpa_start)
{
	unsigned long irqflags;
	int i;
	u64 gpa;

	gpa_start &= ~((2ULL << 20) - 1);

	spin_lock_irqsave(&watch_lock, irqflags);

	for (i = 0; i < NPT_HOOK_MAX_WATCHES; i++) {
		if (watch_table[i].active && watch_table[i].gpa_start == gpa_start) {
			struct npt_watch_entry *w = &watch_table[i];

			/* NPT'yi geri al ve JMP Bitmap'i temizle */
			for (gpa = w->gpa_start; gpa < w->gpa_end; gpa += (2ULL << 20)) {
				npt_set_page_rw(ctx, gpa);
				{
					u64 p;
					for (p = 0; p < 512; p++)
						__clear_bit((gpa >> 12) + p,
							    (unsigned long *)hook_bitmap);
				}
			}

			w->active = false;
			watch_count--;

			spin_unlock_irqrestore(&watch_lock, irqflags);
			pr_info("[ACPI_DAEMON] Watch removed: GPA 0x%llx\n", gpa_start);
			return 0;
		}
	}

	spin_unlock_irqrestore(&watch_lock, irqflags);
	return -ENOENT;
}

/*
 * npt_hook_is_watched - Verilen GPA, izleme listesinde mi?
 * VMEXIT handler'ından çağrılır (IRQ disabled, çok hızlı olmalı).
 * Returns: flags (NPT_WATCH_NX | NPT_WATCH_RO) or 0 if not watched.
 */
u32 npt_hook_is_watched(u64 gpa)
{
	int i;

	/* Hot path — lock almıyoruz, watch_table'ı sadece modül init'te
	 * ve procfs'ten yazarız, VMEXIT path'inde sadece okuruz.
	 * Worst case: bir kayıt kaçırırız, bu kabul edilebilir.
	 */
	for (i = 0; i < NPT_HOOK_MAX_WATCHES; i++) {
		if (watch_table[i].active && gpa >= watch_table[i].gpa_start &&
		    gpa < watch_table[i].gpa_end)
			return watch_table[i].flags;
	}
	return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Procfs Interface: /proc/svm_npt_hook
 *
 *  Komutlar:
 *    echo "add <gpa_start_hex> <gpa_end_hex> <nx|ro|nxro>" > /proc/svm_npt_hook
 *    echo "del <gpa_start_hex>" > /proc/svm_npt_hook
 *    echo "clear" > /proc/svm_npt_hook
 *    cat /proc/svm_npt_hook   → aktif izleme listesini gösterir
 * ═══════════════════════════════════════════════════════════════════════════
 */

static int hook_proc_show(struct seq_file *m, void *v)
{
	int i;
	unsigned long irqflags;

	seq_printf(m, "=== NPT Surgical Hook Watchlist (%d/%d) ===\n", watch_count,
		   NPT_HOOK_MAX_WATCHES);
	seq_printf(m, "%-4s %-18s %-18s %-8s\n", "ID", "GPA_START", "GPA_END", "FLAGS");
	seq_puts(m, "---- ------------------ ------------------ --------\n");

	spin_lock_irqsave(&watch_lock, irqflags);
	for (i = 0; i < NPT_HOOK_MAX_WATCHES; i++) {
		if (!watch_table[i].active)
			continue;
		seq_printf(m, "%-4d 0x%016llx 0x%016llx %s%s\n", i, watch_table[i].gpa_start,
			   watch_table[i].gpa_end,
			   (watch_table[i].flags & NPT_WATCH_NX) ? "NX " : "",
			   (watch_table[i].flags & NPT_WATCH_RO) ? "RO" : "");
	}
	spin_unlock_irqrestore(&watch_lock, irqflags);

	return 0;
}

static int hook_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hook_proc_show, NULL);
}

static ssize_t hook_proc_write(struct file *file, const char __user *buf, size_t count,
			       loff_t *ppos)
{
	char kbuf[128];
	size_t len = min(count, sizeof(kbuf) - 1);
	u64 gpa_start, gpa_end;
	char flag_str[16];
	u32 flags = 0;

	if (!g_svm)
		return -ENODEV;

	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = '\0';

	if (strncmp(kbuf, "add ", 4) == 0) {
		if (sscanf(kbuf + 4, "%llx %llx %15s", &gpa_start, &gpa_end, flag_str) != 3)
			return -EINVAL;

		if (strstr(flag_str, "nx"))
			flags |= NPT_WATCH_NX;
		if (strstr(flag_str, "ro"))
			flags |= NPT_WATCH_RO;
		if (!flags)
			return -EINVAL;

		if (npt_hook_add_watch(&g_svm->npt, gpa_start, gpa_end, flags))
			return -ENOMEM;

	} else if (strncmp(kbuf, "del ", 4) == 0) {
		if (sscanf(kbuf + 4, "%llx", &gpa_start) != 1)
			return -EINVAL;

		if (npt_hook_remove_watch(&g_svm->npt, gpa_start))
			return -ENOENT;

	} else if (strncmp(kbuf, "clear", 5) == 0) {
		int i;
		unsigned long irqflags;

		spin_lock_irqsave(&watch_lock, irqflags);
		for (i = 0; i < NPT_HOOK_MAX_WATCHES; i++) {
			if (watch_table[i].active) {
				u64 gpa;

				for (gpa = watch_table[i].gpa_start; gpa < watch_table[i].gpa_end;
				     gpa += (2ULL << 20)) {
					npt_set_page_rw(&g_svm->npt, gpa);
					{
						u64 p;
						for (p = 0; p < 512; p++)
							__clear_bit((gpa >> 12) + p,
								    (unsigned long *)hook_bitmap);
					}
				}

				watch_table[i].active = false;
			}
		}
		watch_count = 0;
		spin_unlock_irqrestore(&watch_lock, irqflags);
		pr_info("[ACPI_DAEMON] All watches cleared.\n");
	} else {
		return -EINVAL;
	}

	return count;
}

static const struct proc_ops hook_proc_ops = {
    .proc_open = hook_proc_open,
    .proc_read = seq_read,
    .proc_write = hook_proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  Module Init / Exit
 * ═══════════════════════════════════════════════════════════════════════════
 */

int npt_hook_init(void)
{
	memset(watch_table, 0, sizeof(watch_table));
	watch_count = 0;

	hook_proc_entry = proc_create("svm_npt_hook", 0600, NULL, &hook_proc_ops);
	if (!hook_proc_entry) {
		pr_err("[ACPI_DAEMON] Failed to create /proc/svm_npt_hook\n");
		return -ENOMEM;
	}

	pr_info("[ACPI_DAEMON] Phase 18 Surgical NPT Hooking Engine initialized.\n");
	return 0;
}

void npt_hook_exit(void)
{
	if (hook_proc_entry) {
		proc_remove(hook_proc_entry);
		hook_proc_entry = NULL;
	}

	/* Tüm izlemeleri kaldır */
	if (g_svm) {
		int i;

		for (i = 0; i < NPT_HOOK_MAX_WATCHES; i++) {
			if (watch_table[i].active) {
				u64 gpa;

				for (gpa = watch_table[i].gpa_start; gpa < watch_table[i].gpa_end;
				     gpa += (2ULL << 20))
					npt_set_page_rw(&g_svm->npt, gpa);
			}
		}
	}

	pr_info("[ACPI_DAEMON] Phase 18 cleanup done.\n");
}
