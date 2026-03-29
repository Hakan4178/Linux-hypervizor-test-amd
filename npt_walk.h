#ifndef NPT_WALK_H
#define NPT_WALK_H

#include <linux/types.h>

/* NPT page table entry flags (AMD64 long mode) */
#define NPT_PRESENT (1ULL << 0)
#define NPT_WRITE (1ULL << 1)
#define NPT_USER (1ULL << 2)
#define NPT_PS (1ULL << 7) /* Page Size: 2MB in PD, 1GB in PDPT */
#define NPT_NX (1ULL << 63)

#define NPT_DEFAULT_FLAGS (NPT_PRESENT | NPT_WRITE | NPT_USER)

#define NPT_MAX_PAGES 8192 /* max pages we'll allocate for NPT structures */

struct npt_context {
  u64 *pml4;
  phys_addr_t pml4_pa;
  struct page *pages[NPT_MAX_PAGES];
  int page_count;
};

/* Build identity-mapped NPT covering phys_limit bytes of RAM using 2MB leaves
 */
int npt_build_identity_map(struct npt_context *ctx, u64 phys_limit);

/* Tear down and free all NPT pages */
void npt_destroy(struct npt_context *ctx);

/* Mark a GPA as NX in the NPT (hide our own code pages) */
int npt_set_page_nx(struct npt_context *ctx, u64 gpa);

#endif
