#include "ring_minus_one.h"
#include "svm_trace.h"
#include "svm_decode.h"

/*
 * handle_npf - Nested Page Fault izole edilmiş isleyicisi
 * 
 * VMP gibi sistemlerde olusan #NPF trap olaylarini burasi yakalar 
 * ve instruction'lari Host tabaninda isleyip/loglayarak 
 * Stealth Telemetry olusturur.
 */
void handle_npf(struct svm_context *ctx, u64 npf_entry_tsc)
{
	u64 gpa = ctx->vmcb->control.exit_info_2;
	u64 info1 = ctx->vmcb->control.exit_info_1;

	/*
	 * Phase 18 — VMP Decrypt/Execute İzleyici
	 * Phase 26 — Software Prefetching!
	 * ═══════════════════════════════════════════════════════════════
	 * Start prefetching the physical target immediately before even
	 * resolving watch flags. By the time we enter decoding or memcpy,
	 * the memory controller has asynchronously populated the L2/L1-D cache!
	 */
	u64 hpa = npt_get_hpa(&ctx->npt, gpa);
	if (hpa && pfn_valid(hpa >> PAGE_SHIFT)) {
		prefetch(phys_to_virt(hpa & PAGE_MASK));
	}

	if (info1 & NPF_INFO1_EXECUTE) {
		u32 watch_flags = npt_hook_is_watched(gpa);

		if (watch_flags & NPT_WATCH_NX) {
			/* GPA güvenlik kontrolü */
			if (gpa >= NPT_PHYS_LIMIT || !pfn_valid(gpa >> PAGE_SHIFT))
				return;

			/* Telemetry: Execute trap logla */
			void *hva = phys_to_virt(gpa & PAGE_MASK);

			svm_trace_emit_dirty(ctx->vmcb->save.cr3,
					     ctx->vmcb->save.rip,
					     gpa & PAGE_MASK, hva);

			/*
			 * Phase 21: Instruction Decoder (Split-View)
			 * Before lifting NX and exposing the page, try to decode and emulate 
			 * register-only instructions natively from host memory.
			 *
			 * SAFARI / BOUNDARY CHECK: gpa is Guest Physical, we must precisely 
			 * map it to Host Physical, and handle cross-page instruction fetches.
			 */
			{
				u8 insn_buf[15] = {0};
				u64 hpa1 = npt_get_hpa(&ctx->npt, gpa);

				if (hpa1 && pfn_valid(hpa1 >> PAGE_SHIFT)) {
					void *hva1 = phys_to_virt(hpa1);
					size_t bytes_in_page = PAGE_SIZE - (hpa1 & ~PAGE_MASK);
					size_t read_len1 = (bytes_in_page < 15) ? bytes_in_page : 15;

					memcpy(insn_buf, hva1, read_len1);

					/* Handle instructions crossing a physical page boundary safely */
					if (read_len1 < 15) {
						u64 gpa2 = gpa + read_len1;
						u64 hpa2 = npt_get_hpa(&ctx->npt, gpa2);
						
						if (hpa2 && pfn_valid(hpa2 >> PAGE_SHIFT)) {
							void *hva2 = phys_to_virt(hpa2);
							memcpy(insn_buf + read_len1, hva2, 15 - read_len1);
						}
					}

					/* Attempt hypervisor-level emulation */
					u32 decode_result = svm_decode_insn(insn_buf, &ctx->gregs, &ctx->vmcb->save);
					u32 insn_len = decode_result & DECODE_LEN_MASK;

					if ((decode_result & DECODE_ACTION_EMULATED) && insn_len > 0) {
						/* Successfully emulated register operation! No NX lift needed. */
						if (!(decode_result & DECODE_ACTION_BRANCH))
							ctx->vmcb->save.rip += insn_len;

						/* Telemetry trace (0, 0 since it's just sequential emulation unless branch) */
						svm_trace_emit_lbr(ctx->vmcb->save.cr3, ctx->vmcb->save.rip, 0, 0, insn_buf, 15);

						/* Enforce TSC Compensation / Drift Control before seamless resume */
						u64 npf_exit_tsc = rdtsc();
						u64 hv_delta = npf_exit_tsc - npf_entry_tsc;
						if (hv_delta > TSC_COMP_MAX_DELTA)
							hv_delta = TSC_COMP_MAX_DELTA;
						
						ctx->vmcb->control.tsc_offset -= hv_delta;
						ctx->vmcb->control.clean &= ~VMCB_CLEAN_TSC;

						return; /* Resume guest transparently */
					}
				}
			}

			/* NPT'den geçici olarak NX'i kaldır (execute izni ver) - Fallback */
			{
				u64 *pml4 = ctx->npt.pml4;
				int pml4i = (gpa >> 39) & 0x1FF;
				int pdpti = (gpa >> 30) & 0x1FF;
				int pdi = (gpa >> 21) & 0x1FF;

				u64 pdpt_phys = pml4[pml4i] & 0x000FFFFFFFFFF000ULL;

				if (!pdpt_phys || !pfn_valid(pdpt_phys >> PAGE_SHIFT))
					goto skip_nx_rearm;
				u64 *pdpt = (u64 *)phys_to_virt(pdpt_phys);

				u64 pd_phys = pdpt[pdpti] & 0x000FFFFFFFFFF000ULL;

				if (!pd_phys || !pfn_valid(pd_phys >> PAGE_SHIFT))
					goto skip_nx_rearm;
				u64 *pd = (u64 *)phys_to_virt(pd_phys);

				pd[pdi] &= ~NPT_NX; /* Geçici execute izni */
			}

			/*
			 * INVLPGA: Sadece bu ASID+GPA için TLB entry'sini düşür.
			 * Full flush (TLB_CTL=1) yapmak yerine cerrahi invalidation.
			 *
			 * NOT: INVLPGA sadece yerel çekirdeğin TLB'sini temizler.
			 * Multi-core senaryoda stale TLB riski var. Ancak Matrix
			 * süreci CPU 0'a pinli olduğu için (svm_chardev.c) bu
			 * güvenli. Faz 19'da multi-core desteği gelirse INVLPGB
			 * veya IPI-flush mekanizmasına geçilmeli.
			 */
			asm volatile("invlpga" :: "a"(gpa & PAGE_MASK),
				     "c"((u32)ctx->vmcb->control.asid));

skip_nx_rearm:
			ctx->pending_rearm_gpa = gpa & PAGE_MASK;
			ctx->pending_rearm_nx = 1; /* Instruct #DB handler to lift EXACTLY NX */
			ctx->vmcb->save.rflags |= RFLAGS_TF;
			ctx->vmcb->control.intercepts[INTERCEPT_EXCEPTION_OFFSET >> 5] |=
			    EXCEPT_DB_BIT;
			ctx->vmcb->control.clean &= ~(VMCB_CLEAN_NP | VMCB_CLEAN_INTERCEPTS);
		}

		/* TSC Compensation: Hypervisor'da geçen süreyi Guest TSC'den sil */
		{
			u64 npf_exit_tsc = rdtsc();
			u64 hv_delta = npf_exit_tsc - npf_entry_tsc;

			/* Drift Guard: Üst sınır aşılırsa cap uygula */
			if (hv_delta > TSC_COMP_MAX_DELTA)
				hv_delta = TSC_COMP_MAX_DELTA;

			ctx->vmcb->control.tsc_offset -= hv_delta;
			ctx->vmcb->control.clean &= ~VMCB_CLEAN_TSC;
		}
		return;
	}

	if (info1 & NPF_INFO1_WRITE) {
		/*
		 * SECURITY: Validate GPA is within our identity map.
		 */
		if (gpa >= NPT_PHYS_LIMIT)
			return;

		if (!pfn_valid(gpa >> PAGE_SHIFT))
			return;

		u64 hpa = npt_get_hpa(&ctx->npt, gpa);
		if (hpa && pfn_valid(hpa >> PAGE_SHIFT)) {
			void *hva = phys_to_virt(hpa & PAGE_MASK);
			svm_trace_emit_dirty(ctx->vmcb->save.cr3, ctx->vmcb->save.rip,
					     gpa & PAGE_MASK, hva);
		}

		{
			u64 *pml4 = ctx->npt.pml4;
			int pml4i = (gpa >> 39) & 0x1FF;
			int pdpti = (gpa >> 30) & 0x1FF;
			int pdi = (gpa >> 21) & 0x1FF;

			u64 pdpt_phys = pml4[pml4i] & 0x000FFFFFFFFFF000ULL;

			if (!pdpt_phys || !pfn_valid(pdpt_phys >> PAGE_SHIFT))
				goto skip_rearm;
			u64 *pdpt = (u64 *)phys_to_virt(pdpt_phys);

			u64 pd_phys = pdpt[pdpti] & 0x000FFFFFFFFFF000ULL;

			if (!pd_phys || !pfn_valid(pd_phys >> PAGE_SHIFT))
				goto skip_rearm;
			u64 *pd = (u64 *)phys_to_virt(pd_phys);

			pd[pdi] |= NPT_WRITE;
		}

		/*
		 * INVLPGA: Cerrahi TLB invalidation (Write-fault path)
		 */
		asm volatile("invlpga" :: "a"(gpa & PAGE_MASK),
			     "c"((u32)ctx->vmcb->control.asid));

skip_rearm:
		ctx->pending_rearm_gpa = gpa & PAGE_MASK;
		ctx->pending_rearm_nx = 0; /* Instruct #DB handler to restore NPT_WRITE, not NPT_NX */
		ctx->vmcb->save.rflags |= RFLAGS_TF;
		ctx->vmcb->control.intercepts[INTERCEPT_EXCEPTION_OFFSET >> 5] |=
		    EXCEPT_DB_BIT;
		ctx->vmcb->control.clean &= ~(VMCB_CLEAN_NP | VMCB_CLEAN_INTERCEPTS);

		/* TSC Compensation: Write-fault path */
		{
			u64 npf_exit_tsc = rdtsc();
			u64 hv_delta = npf_exit_tsc - npf_entry_tsc;

			/* Drift Guard: Üst sınır aşılırsa cap uygula */
			if (hv_delta > TSC_COMP_MAX_DELTA)
				hv_delta = TSC_COMP_MAX_DELTA;

			ctx->vmcb->control.tsc_offset -= hv_delta;
			ctx->vmcb->control.clean &= ~VMCB_CLEAN_TSC;
		}
	}
}
