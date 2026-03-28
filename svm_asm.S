#include <linux/linkage.h>

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

/*
 * void vmrun_with_regs(u64 vmcb_pa, struct guest_regs *regs)
 * %rdi = vmcb_pa
 * %rsi = regs pointer
 */
SYM_FUNC_START(vmrun_with_regs)
    SAVE_HOST_REGS

    /* Move vmcb_pa to %rax because VMRUN requires it in %rax */
    mov %rdi, %rax

    /* Save the regs pointer on the host stack before we overwrite %rsi */
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

    /* ======= VMRUN ======= */
    clgi
    vmrun %rax
    stgi
    /* ===================== */

    /*
     * VMEXIT!
     * Hardware restored Host RIP, RSP, and CS/SS/DS/ES (partially).
     * Guest GPRs are currently in our registers.
     * We need our 'regs' pointer back to save them!
     * Exchange the top of the host stack (which holds our regs pointer) with %rsi.
     */
    xchg %rsi, (%rsp)
    /* Now %rsi holds the regs pointer, and the guest's %rsi is at the top of the stack! */

    mov %rbx, 0x00(%rsi)
    mov %rcx, 0x08(%rsi)
    mov %rdx, 0x10(%rsi)
    
    /* Pop guest %rsi from stack (using %rbx as temporary scratch since we just saved it) */
    pop %rbx
    mov %rbx, 0x18(%rsi)

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
