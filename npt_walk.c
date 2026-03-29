/*
 * npt_walk.c — NPT Identity Map Builder for Ring -1 Stealth Introspection
 *
 * Creates a 4-level AMD64 NPT (Nested Page Table) that identity-maps
 * physical RAM (GPA == HPA) using 2MB leaf entries for performance.
 * Used by svm_dump to read process memory invisibly through hardware
 * address translation instead of software page table walks.
 */

#include <asm/page.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "npt_walk.h"

/*
 * NPT PAT/Cache type bits for 2MB pages (AMD64 APM Vol.2 Table 5-6):
 *   PWT (bit 3), PCD (bit 4), PAT (bit 12 for large pages)
 *
 * WB  (Write-Back)     = PWT=0 PCD=0 PAT=0  → normal RAM
 * UC  (Uncacheable)     = PWT=1 PCD=1 PAT=0  → MMIO / I/O regions
 */
#define NPT_PWT (1ULL << 3)
#define NPT_PCD (1ULL << 4)
#define NPT_PAT_LARGE (1ULL << 12)

#define NPT_CACHE_WB 0ULL
#define NPT_CACHE_UC (NPT_PWT | NPT_PCD)

/*
 * Allocate a zeroed page and track it in the context for cleanup.
 * Returns the kernel virtual address, or NULL on failure.
 */
static u64 *npt_alloc_page(struct npt_context *ctx) {
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
 * npt_build_identity_map - Build a 4-level identity mapped NPT
 * @ctx: NPT context to populate
 * @phys_limit: upper bound of physical address space to map (bytes)
 *
 * Creates PML4 → PDPT → PD entries with 2MB leaf pages (PS=1).
 * No PT level is needed for 2MB identity mapping.
 *
 * Address space breakdown for 2MB pages:
 *   PML4 index: bits [47:39]  — up to 512 entries
 *   PDPT index: bits [38:30]  — up to 512 entries per PML4e
 *   PD   index: bits [29:21]  — up to 512 entries per PDPTe
 *   Each PD entry maps 2MB when PS=1.
 *
 * For 4GB RAM: 1 PML4e, 4 PDPTe, 2048 PDe → ~6 pages total.
 * For 64GB RAM: 1 PML4e, 64 PDPTe, 32768 PDe → ~129 pages total.
 */
int npt_build_identity_map(struct npt_context *ctx, u64 phys_limit) {
  u64 addr;
  int pml4_idx, pdpt_idx, pd_idx;
  u64 *pml4, *pdpt, *pd;

  memset(ctx, 0, sizeof(*ctx));

  /* Allocate PML4 (root) */
  pml4 = npt_alloc_page(ctx);
  if (!pml4)
    return -ENOMEM;

  ctx->pml4 = pml4;
  ctx->pml4_pa = virt_to_phys(pml4);

  pr_info("[NPT] Building identity map up to 0x%llx (%llu MB)\n", phys_limit,
          phys_limit >> 20);

  for (addr = 0; addr < phys_limit; addr += (2ULL << 20)) {
    pml4_idx = (addr >> 39) & 0x1FF;
    pdpt_idx = (addr >> 30) & 0x1FF;
    pd_idx = (addr >> 21) & 0x1FF;

    /* Allocate PDPT if this PML4 slot is empty */
    if (!(pml4[pml4_idx] & NPT_PRESENT)) {
      pdpt = npt_alloc_page(ctx);
      if (!pdpt)
        goto fail;
      pml4[pml4_idx] = virt_to_phys(pdpt) | NPT_DEFAULT_FLAGS;
    } else {
      pdpt = phys_to_virt(pml4[pml4_idx] & ~0xFFFULL);
    }

    /* Allocate PD if this PDPT slot is empty */
    if (!(pdpt[pdpt_idx] & NPT_PRESENT)) {
      pd = npt_alloc_page(ctx);
      if (!pd)
        goto fail;
      pdpt[pdpt_idx] = virt_to_phys(pd) | NPT_DEFAULT_FLAGS;
    } else {
      pd = phys_to_virt(pdpt[pdpt_idx] & ~0xFFFULL);
    }

    /*
     * MTRR safety: Mark I/O regions (above max_pfn) as Uncacheable.
     * RAM regions get Write-Back (default, bits clear).
     * This prevents system lockups on MMIO accesses.
     */
    {
      u64 cache_flags;
      unsigned long pfn = addr >> PAGE_SHIFT;

      if (!pfn_valid(pfn))
        cache_flags = NPT_CACHE_UC; /* I/O / MMIO region */
      else
        cache_flags = NPT_CACHE_WB; /* Normal RAM */

      /* Create 2MB leaf entry: GPA == HPA, PS=1, cache type set */
      BUG_ON(addr & ((2ULL << 20) - 1)); /* Assert 2MB alignment */
      pd[pd_idx] = addr | NPT_DEFAULT_FLAGS | NPT_PS | cache_flags;
    }
  }

  pr_info("[NPT] Identity map built: %d pages allocated, root PA=0x%llx\n",
          ctx->page_count, (u64)ctx->pml4_pa);

  /*
   * HPET MMIO guard: Mark 0xFED00000 (HPET base) as NX.
   * Prevents guest from reading hardware timer via MMIO,
   * which would reveal real elapsed time despite TSC offset.
   */
  npt_set_page_nx(ctx, 0xFED00000ULL);

  return 0;

fail:
  pr_err("[NPT] Allocation failed at addr 0x%llx\n", addr);
  npt_destroy(ctx);
  return -ENOMEM;
}
EXPORT_SYMBOL_GPL(npt_build_identity_map);

/*
 * npt_destroy - Free all pages allocated for the NPT
 */
void npt_destroy(struct npt_context *ctx) {
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
EXPORT_SYMBOL_GPL(npt_destroy);

/*
 * npt_set_page_nx - Mark a GPA's 2MB region as NX in the NPT
 * @ctx: NPT context
 * @gpa: guest physical address within a 2MB region
 *
 * Used to hide our own hypervisor code pages from guest execution.
 */
int npt_set_page_nx(struct npt_context *ctx, u64 gpa) {
  int pml4_idx = (gpa >> 39) & 0x1FF;
  int pdpt_idx = (gpa >> 30) & 0x1FF;
  int pd_idx = (gpa >> 21) & 0x1FF;
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
EXPORT_SYMBOL_GPL(npt_set_page_nx);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NPT Identity Map Builder for SVM Stealth Introspection");
