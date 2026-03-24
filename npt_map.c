/*
 * npt_map.c — NPT Identity Map Builder
 *
 * 4-level AMD64 NPT (Nested Page Table) that identity-maps
 * physical RAM (GPA == HPA) using 2MB leaf entries.
 * MTRR-safe: RAM=WB, I/O=UC. HPET auto-NX.
 */

#include "ring_minus_one.h"

/* ═══════════════════════════════════════════════════════════════════════════
 *  NPT Fonksiyonları
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * npt_alloc_page - NPT için sıfırlanmış bir sayfa ayır ve context'e kaydet
 */
static u64 *npt_alloc_page(struct npt_context *ctx)
{
    struct page *p;

    if (ctx->page_count >= NPT_MAX_PAGES) {
        pr_err("[NPT] page limit (%d) exceeded\n", NPT_MAX_PAGES);
        return NULL;
    }

    p = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!p)
        return NULL;

    ctx->pages[ctx->page_count++] = p;
    return (u64 *)page_address(p);
}

/*
 * npt_build_identity_map - 4-level AMD64 NPT identity map oluştur
 * @ctx: NPT context (doldurulacak)
 * @phys_limit: haritalanacak fiziksel adres üst sınırı (byte)
 *
 * PML4 → PDPT → PD zinciri kurar, her PD entry'si 2MB leaf (PS=1).
 * MTRR güvenliği: RAM bölgeleri WB, I/O bölgeleri UC.
 * HPET MMIO (0xFED00000) otomatik NX olarak işaretlenir.
 */
int npt_build_identity_map(struct npt_context *ctx, u64 phys_limit)
{
    u64 addr;
    int pml4_idx, pdpt_idx, pd_idx;
    u64 *pml4, *pdpt, *pd;

    memset(ctx, 0, sizeof(*ctx));

    pml4 = npt_alloc_page(ctx);
    if (!pml4)
        return -ENOMEM;

    ctx->pml4 = pml4;
    ctx->pml4_pa = virt_to_phys(pml4);

    pr_info("[NPT] Building identity map up to 0x%llx (%llu MB)\n",
        phys_limit, phys_limit >> 20);

    for (addr = 0; addr < phys_limit; addr += (2ULL << 20)) {
        pml4_idx = (addr >> 39) & 0x1FF;
        pdpt_idx = (addr >> 30) & 0x1FF;
        pd_idx   = (addr >> 21) & 0x1FF;

        if (!(pml4[pml4_idx] & NPT_PRESENT)) {
            pdpt = npt_alloc_page(ctx);
            if (!pdpt)
                goto fail;
            pml4[pml4_idx] = virt_to_phys(pdpt) | NPT_DEFAULT_FLAGS;
        } else {
            pdpt = phys_to_virt(pml4[pml4_idx] & ~0xFFFULL);
        }

        if (!(pdpt[pdpt_idx] & NPT_PRESENT)) {
            pd = npt_alloc_page(ctx);
            if (!pd)
                goto fail;
            pdpt[pdpt_idx] = virt_to_phys(pd) | NPT_DEFAULT_FLAGS;
        } else {
            pd = phys_to_virt(pdpt[pdpt_idx] & ~0xFFFULL);
        }

        {
            u64 cache_flags;
            unsigned long pfn = addr >> PAGE_SHIFT;

            if (!pfn_valid(pfn))
                cache_flags = NPT_CACHE_UC;
            else
                cache_flags = NPT_CACHE_WB;

            BUG_ON(addr & ((2ULL << 20) - 1));
            pd[pd_idx] = addr | NPT_DEFAULT_FLAGS | NPT_PS | cache_flags;
        }
    }

    pr_info("[NPT] Identity map built: %d pages allocated, root PA=0x%llx\n",
        ctx->page_count, (u64)ctx->pml4_pa);

    npt_set_page_nx(ctx, 0xFED00000ULL);
    return 0;

fail:
    pr_err("[NPT] Allocation failed at addr 0x%llx\n", addr);
    npt_destroy(ctx);
    return -ENOMEM;
}

/*
 * npt_destroy - NPT yapısını yok et, tüm sayfaları serbest bırak
 */
void npt_destroy(struct npt_context *ctx)
{
    int i;

    for (i = 0; i < ctx->page_count; i++) {
        if (ctx->pages[i])
            __free_page(ctx->pages[i]);
    }

    ctx->pml4 = NULL;
    ctx->pml4_pa = 0;
    ctx->page_count = 0;

    pr_info("[NPT] Destroyed, all pages freed\n");
}

/*
 * npt_set_page_nx - NPT'de belirli bir GPA'nın 2MB bölgesini NX olarak işaretle
 * @ctx: NPT context
 * @gpa: guest physical address (2MB bölge içinde herhangi bir adres)
 *
 * HPET gibi timer MMIO bölgelerini erişilemez yapmak için kullanılır.
 */
int npt_set_page_nx(struct npt_context *ctx, u64 gpa)
{
    int pml4_idx = (gpa >> 39) & 0x1FF;
    int pdpt_idx = (gpa >> 30) & 0x1FF;
    int pd_idx   = (gpa >> 21) & 0x1FF;
    u64 *pdpt, *pd;

    if (!ctx->pml4 || !(ctx->pml4[pml4_idx] & NPT_PRESENT))
        return -ENOENT;

    pdpt = phys_to_virt(ctx->pml4[pml4_idx] & ~0xFFFULL);
    if (!(pdpt[pdpt_idx] & NPT_PRESENT))
        return -ENOENT;

    pd = phys_to_virt(pdpt[pdpt_idx] & ~0xFFFULL);
    pd[pd_idx] |= NPT_NX;

    pr_info("[NPT] GPA 0x%llx marked NX\n", gpa & ~((2ULL << 20) - 1));
    return 0;
}
