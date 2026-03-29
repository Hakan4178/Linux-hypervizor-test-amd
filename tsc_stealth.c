/*
 * tsc_stealth.c — Per-CPU TSC Offset Compensation (V4.0)
 *
 * Per-CPU offset eliminates cross-core drift.
 * IRQ disabled + preempt disabled eliminates interrupt-induced spikes.
 * Result: guest sees perfectly linear TSC progression.
 */

#include "ring_minus_one.h"

DEFINE_PER_CPU(s64, pcpu_tsc_offset);

/*
 * vmrun_tsc_compensated - Execute VMRUN and compensate TSC
 * @vmcb: Virtual Machine Control Block
 * @vmcb_pa: Physical address of VMCB
 *
 * Wraps vmrun_safe with per-CPU TSC offset tracking.
 * IRQ ve preemption devre dışı bırakılarak interrupt spike'ları önlenir.
 */
u64 vmrun_tsc_compensated(struct svm_context *ctx) {
  u64 tsc_before, tsc_after, exit_code;
  unsigned long flags;
  s64 *offset;

  preempt_disable();
  local_irq_save(flags);

  offset = this_cpu_ptr(&pcpu_tsc_offset);
  ctx->vmcb->control.tsc_offset = *offset;

  /* Mark stable fields clean — only TSC changes per-VMRUN */
  ctx->vmcb->control.clean = VMCB_CLEAN_STABLE;

  tsc_before = rdtsc();
  vmrun_safe(ctx->vmcb_pa);
  tsc_after = rdtsc();

  /* Subtract hypervisor time — per-CPU, no cross-core drift */
  *offset -= (s64)(tsc_after - tsc_before);

  local_irq_restore(flags);
  preempt_enable();

  exit_code = ((u64)ctx->vmcb->control.exit_code_hi << 32) |
              ctx->vmcb->control.exit_code;
  return exit_code;
}

/*
 * tsc_offset_reset - Bu CPU'nun TSC offset'ini sıfırla
 */
void tsc_offset_reset(void) { this_cpu_write(pcpu_tsc_offset, 0); }
