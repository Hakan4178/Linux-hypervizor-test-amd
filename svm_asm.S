#include <linux/linkage.h>
#include "vmexit_fastpath.S"
.macro SAVE_HOST_REGS
    push %rbp
    push %r15
    push %r14
    push %r13
    push %r12
    push %rbx
.endm

.macro RESTORE_HOST_REGS
    pop %rbx
    pop %r12
    pop %r13
    pop %r14
    pop %r15
    pop %rbp
.endm

.extern hook_bitmap

/*
 * void vmrun_with_regs(u64 vmcb_pa, struct guest_regs *regs, struct vmcb *vmcb_va)
 * %rdi = vmcb_pa
 * %rsi = regs pointer
 * %rdx = vmcb_va
 */
SYM_FUNC_START(vmrun_with_regs)
    SAVE_HOST_REGS

    /* Move vmcb_pa to %rax because VMRUN requires it in %rax */
    mov %rdi, %rax

    /* Save vmcb_pa, vmcb_va and regs_ptr on the host stack */
    push %rdi
    push %rdx
    push %rsi

    /* Load guest GPRs from struct (RSI is our pointer) */
    mov 0x00(%rsi), %rbx
    mov 0x08(%rsi), %rcx
    mov 0x10(%rsi), %rdx
    /* Skip %rsi (0x18) for now */
    mov 0x20(%rsi), %rdi
    mov 0x28(%rsi), %rbp
    mov 0x30(%rsi), %r8
    mov 0x38(%rsi), %r9
    mov 0x40(%rsi), %r10
    mov 0x48(%rsi), %r11
    mov 0x50(%rsi), %r12
    mov 0x58(%rsi), %r13
    mov 0x60(%rsi), %r14
    mov 0x68(%rsi), %r15
    
    /* Finally load guest %rsi */
    mov 0x18(%rsi), %rsi

    /*
     * Phase 26 BTB Warming: Align VMRUN loop entry to 64-byte cache line.
     * This is THE hottest branch target in the entire hypervisor.
     * Alignment ensures clgi/vmrun/stgi fit within a single L1-I line.
     */
    .align 64
.Ldo_vmrun:
    /* ======= VMRUN ======= */
    clgi
    vmrun %rax
    stgi
    /* ===================== */

    /* Phase 27: Macro-based VMEXIT Dispatcher (True Zero-Stack & O(1) Fast-Paths) */
    /* Read regs_ptr from stack into RAX without modifying RSP */
    mov 0(%rsp), %rax
    
    /* Save guest registers directly into guest_regs memory (L1-D cache hit, 0 RSP pipeline stalls) */
    mov %r14, 0x60(%rax)
    mov %r8,  0x30(%rax)
    mov %rcx, 0x08(%rax)

    mov 8(%rsp), %r14        /* %r14 = vmcb_va */
    
    .align 64
.Lvmexit_dispatch:
    movl 0x70(%r14), %eax    /* Exit Code (u32) */

    /* 1. NPF (Nested Page Fault) - Hot Path */
    cmp $0x400, %eax
    je  .Lcheck_npf

    /* Phase 28C: DRx Hook (#DB Exception) -> Fast Path Check */
    cmp $0x41, %eax
    je  .Lcheck_stealth_db

    /* 2. DRx Read Shadowing (0x20 ... 0x27) */
    sub $0x20, %eax
    cmp $7, %eax
    jbe .Lhandle_drx

    /* 3. Unhandled Exits -> Fallback to C Slow Path */
    jmp .Lslow_path

.Lcheck_npf:
    /* Phase 26: Zero-Stack Bitmap Check for NPF */
    mov 0x80(%r14), %rcx     /* GPA */
    shr $12, %rcx            /* GPA >> 12 (Page Number) */

    /* Paranoid Boundary Check: 64GB / 4KB = 16M pages = 16777216 bits in bitmap */
    cmp $16777216, %rcx      /* Max 64GB Guest RAM limit */
    jae .Lslow_path

    leaq hook_bitmap(%rip), %r8
    bt %rcx, (%r8)
    jc .Lslow_path

    /* Unwatched Page -> Fast Resume via Macro */
    MACRO_FAST_VMRUN
    .align 64

.Lcheck_stealth_db:
    /* Phase 28C: Zero-Stack #DB Intercept (Stealth Exit Hook)
       Check if guest hit our hidden hardware breakpoint.
       Guest RIP is at offset 0x578 (0x400 + 0x178) */
    mov 0x578(%r14), %rcx
    movq ghost_exit_addr(%rip), %r8
    cmp %rcx, %r8
    je .Lstealth_exit_hit

    /* Not our breakpoint! (e.g. Guest AC single-stepping)
       Zero-Stack Exception Injection: Forward #DB back to Guest OS!
       Event Inj (offset 0xb0) = Valid (1<<31) | Exception(3<<8) | Vector(1)
       0x80000301 */
    movl $0x80000301, 0xb0(%r14)
    MACRO_FAST_VMRUN

.Lstealth_exit_hit:
    /* WE HIT DO_GROUP_EXIT! Return to C with ret_loop = 3.
       We must restore scratch registers because C expects them intact.
       Actually, just falling through to .Lslow_path and returning 3 in rax. */
    mov $3, %eax
    
    /* Restore guest volatile regs from our struct before exiting */
    mov 0(%rsp), %rsi        /* regs pointer */
    mov %r14, 0x60(%rsi)
    mov %r8,  0x30(%rsi)
    mov %rcx, 0x08(%rsi)
    
    /* Discard vmcb pointers from stack */
    add $16, %rsp
    
    /* Return cleanly */
    RESTORE_HOST_REGS
    ret

    .align 64

.Lhandle_drx:
    /* Phase 25: True Zero-Stack DRx Emulation */
    MACRO_HANDLE_DRX
    /* MACRO_HANDLE_DRX handles the fast VMRUN loop internally! */

    /* Phase 26 BTB: Align C-fallback entry to cache line boundary */
    .align 64
.Lslow_path:
    /* Note: We do not need to restore r14, r8, rcx from memory because they still holding the 
       guest's values (they were used as scratch but overwritten with identical values if we restored, 
       WAIT! We clobbered them during checks! We must restore them! */
    mov 0x60(%rax), %r14
    mov 0x30(%rax), %r8
    mov 0x08(%rax), %rcx

    /*
     * VMEXIT → C path.
     * Hardware restored Host RIP, RSP, and CS/SS/DS/ES (partially).
     * Guest GPRs are currently in our registers.
     * Stack: [regs_ptr] [vmcb_va] [saved host regs...]
     * We exchange top-of-stack (regs_ptr) with %rsi to get our pointer back.
     */
    xchg %rsi, (%rsp)
    /* Now %rsi holds the regs pointer, and the guest's %rsi is at the top of the stack! */

    mov %rbx, 0x00(%rsi)
    mov %rcx, 0x08(%rsi)
    mov %rdx, 0x10(%rsi)
    
    /* Pop guest %rsi from stack (using %rbx as temporary scratch since we just saved it) */
    pop %rbx
    mov %rbx, 0x18(%rsi)

    /* Pop vmcb_va and vmcb_pa (discard, we don't need them in C path) */
    add $16, %rsp

    mov %rdi, 0x20(%rsi)
    mov %rbp, 0x28(%rsi)
    mov %r8,  0x30(%rsi)
    mov %r9,  0x38(%rsi)
    mov %r10, 0x40(%rsi)
    mov %r11, 0x48(%rsi)
    mov %r12, 0x50(%rsi)
    mov %r13, 0x58(%rsi)
    mov %r14, 0x60(%rsi)
    mov %r15, 0x68(%rsi)

    RESTORE_HOST_REGS
    ret
SYM_FUNC_END(vmrun_with_regs)
