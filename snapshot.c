/*
 * snapshot.c — Bellek Yakalama (Memory Snapshot) Fonksiyonları
 *
 * Process page table walking, VMA enumeration,
 * raw memory dump, checksum hesaplama.
 */

#include "ring_minus_one.h"

/* ═══════════════════════════════════════════════════════════════════════════
 *  Snapshot Yardımcı Fonksiyonlar
 * ═══════════════════════════════════════════════════════════════════════════ */



static u64 compute_checksum(const void *data, size_t len)
{
    const u64 *ptr = data;
    u64 cksum = 0x5356444D48414B41ULL;
    size_t i, words = len / sizeof(u64);

    for (i = 0; i < words; i++)
        cksum ^= ptr[i];
    return cksum & 0xFFFFFFFFFFFFFFFFULL;
}

void snapshot_free_locked(struct snap_context *snap)
{
    if (snap->blob.data) {
        kvfree(snap->blob.data);
        snap->blob.data = NULL;
        snap->blob.size = 0;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Page Table Walk & Snapshot Builder
 * ═══════════════════════════════════════════════════════════════════════════ */

static void count_snapshot_entries(struct mm_struct *mm, u64 *vma_count, u64 *map_count, u64 *data_size)
{
    struct vm_area_struct *vma;
    unsigned long addr;

    VMA_ITERATOR(vmi, mm, 0);
    *vma_count = 0;
    *map_count = 0;
    *data_size = 0;

    mmap_read_lock(mm);
    for_each_vma(vmi, vma) {
        (*vma_count)++;
        for (addr = vma->vm_start; addr < vma->vm_end; ) {
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
                if (next > vma->vm_end || next < addr) next = vma->vm_end;
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
                if (next > vma->vm_end || next < addr) next = vma->vm_end;
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

int build_snapshot_for_task(struct snap_context *snap, struct task_struct *task)
{
    struct mm_struct *mm;
    struct svm_dump_header *hdr;
    struct svm_vma_entry *vma_out;
    struct svm_page_map_entry *map_out;
    void *buf;
    size_t meta_size, data_size_est, total_alloc;
    u64 v_cnt = 0, m_cnt = 0, i_vma = 0, i_map = 0, raw_off = 0, total_data_sz = 0;
    struct vm_area_struct *vma;
    unsigned long addr;
    u8 *raw_buf = NULL;

    mm = get_task_mm(task);
    if (!mm)
        return -EINVAL;

    count_snapshot_entries(mm, &v_cnt, &m_cnt, &total_data_sz);

    /* Z8: Cap entry counts to prevent allocation overflow */
    if (v_cnt > 100000 || m_cnt > 10000000) {
        pr_warn("[SVM_DUMP] Entry count too large: vma=%llu map=%llu, capping\n", v_cnt, m_cnt);
        if (v_cnt > 100000) v_cnt = 100000;
        if (m_cnt > 10000000) m_cnt = 10000000;
    }

    meta_size = sizeof(*hdr) + v_cnt * sizeof(*vma_out) + m_cnt * sizeof(*map_out);
    data_size_est = snap->full_dump_mode ? total_data_sz : 0;
    total_alloc = meta_size + data_size_est + 4096;

    /* Overflow check */
    if (total_alloc < meta_size || total_alloc > (size_t)512 * 1024 * 1024) {
        pr_warn("[SVM_DUMP] Alloc overflow or too large: %zu\n", total_alloc);
        mmput(mm);
        return -ENOMEM;
    }

    buf = kvzalloc(total_alloc, GFP_KERNEL);
    if (!buf) {
        mmput(mm);
        return -ENOMEM;
    }

    hdr = buf;
    vma_out = (void *)(hdr + 1);
    map_out = (void *)(vma_out + v_cnt);

    if (snap->full_dump_mode)
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
        for (addr = vma->vm_start; addr < vma->vm_end; ) {
            pgd_t *pgd;
            p4d_t *p4d;
            pud_t *pud;
            pmd_t *pmd;
            unsigned long pfn_val = 0, pg_size = 0;
            u64 pg_ent = 0;
            int pg_k = 0;

            if (i_map >= m_cnt)
                goto out_unl;

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

fill:
            {
                unsigned long mask = (pg_k == 3) ? PUD_MASK : ((pg_k == 2) ? PMD_MASK : PAGE_MASK);
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

                if (snap->full_dump_mode && raw_buf && pfn_valid(pfn_val)) {
                    struct page *pg = pfn_to_page(pfn_val);
                    if (pg && page_count(pg) > 0 && !PageReserved(pg)) {
                        void *vsrc = pfn_to_kaddr(pfn_val);
                        if (vsrc && (raw_off + chunk_size) <= data_size_est) {
                            if (copy_from_kernel_nofault(raw_buf + raw_off,
                                                         (u8 *)vsrc + offset_in_page,
                                                         chunk_size)) {
                                memset(raw_buf + raw_off, 0, chunk_size);
                            }
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

    if (snap->full_dump_mode) {
        hdr->flags |= SVM_FLAG_RAW_DATA;
        hdr->total_size += raw_off;
    }
    if (snap->npt_mode)
        hdr->flags |= SVM_FLAG_NPT_MODE;

    if (hdr->total_size > total_alloc) {
        pr_warn("[SVM_DUMP] TRUNCATED: total_size %llu > alloc %zu, capping\n",
                hdr->total_size, total_alloc);
        hdr->total_size = total_alloc;
        hdr->flags |= SVM_FLAG_TRUNCATED;
    }

    hdr->checksum = 0;
    hdr->checksum = compute_checksum(buf, (size_t)hdr->total_size);

    mmput(mm);

    snapshot_free_locked(snap);
    snap->blob.data = buf;
    snap->blob.size = (size_t)hdr->total_size;
    snap->last_snapshot_time = ktime_get_real_seconds();
    if (snap->snapshot_count < INT_MAX)
        snap->snapshot_count++;

    return 0;
}
