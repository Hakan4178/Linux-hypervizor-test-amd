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

    /* Phase 29: CPUID (0x72) Assembly Fast Path */
    cmp $0x72, %eax
    je  .Lcheck_cpuid

    /* Phase 29: #PF (0x4E) Pass-Through */
    cmp $0x4E, %eax
    je  .Lcheck_pf

    /* Phase 29 T3: MSR (0x7C) Pass-Through */
    cmp $0x7C, %eax
    je  .Lcheck_msr

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

    .align 64

.Lcheck_pf:
    /* Phase 29 T2: Zero-Stack #PF Forwarding
       Guest caused #PF. Host intercepts it. We just pass it right back to Guest OS!
       Event Inj (offset 0xb0) = Valid (1<<31) | ErrorCodeValid (1<<11) | Exception(3<<8) | Vector(14)
       So 0x80000B0E */
    movl $0x80000B0E, 0xb0(%r14)
    /* We must also supply the Error Code from exit_info_1 (offset 0x78) */
    mov 0x78(%r14), %rcx
    mov %ecx, 0xb4(%r14)
    /* VERY CRITICAL FIX: We MUST populate the Guest CR2 with the fault address 
       otherwise the guest OS page fault handler reads a stale CR2 and panics! 
       exit_info_2 is at 0x80, Guest CR2 is at 0x640 (save_area + 0x240) */
    mov 0x80(%r14), %rcx
    mov %rcx, 0x640(%r14)
    MACRO_FAST_VMRUN

    .align 64

.Lcheck_cpuid:
    /* Phase 29 T1: CPUID Fast Path
       Guest executed CPUID. Leaf is in Guest RAX. We must run host CPUID.
       %r14 = vmcb_va
       %rax (Guest RAX) is already clobbered by Exit Code in %eax!
       Wait, we need to read original Guest RAX from VMCB! */
    mov 0x5a8(%r14), %rax  /* vmcb->save.rax */
                           /* subleaf in guest RCX, which is STILL in %rcx currently! */

    /* Save host RBX, RCX, RDX, since cpuid clobbers them */
    push %rbx
    push %rcx
    push %rdx

    /* Execute native CPUID! */
    cpuid

    /* Check Stealth Filters */
    /* If original EAX = 1, clear Hypervisor Present bit (ECX bit 31) */
    /* Original RAX is lost, but wait, cpuid results are in RAX! 
       Actually, to know original EAX we need to save it! */
    pop %rdx
    pop %rcx
    pop %rbx

    /* Let's restart CPUID handling correctly without destroying host state */
    /* VMCB RAX -> %rax */
    mov 0x5a8(%r14), %rax
    /* Guest RCX -> %rcx (already in %rcx, but let's be safe: 0x08(%rsp) has regs array!) */
    mov 0(%rsp), %r8         /* %r8 = regs_ptr */
    mov 0x08(%r8), %rcx      /* guest rcx */
    
    /* Save HOST non-volatile registers */
    push %rbx
    push %rbp
    
    /* Save Original Leaf for later checks */
    mov %rax, %rbp

    /* Execute Native CPUID */
    cpuid

    /* Filter 1: Leaf == 1 */
    cmp $1, %rbp
    jne 1f
    btr $31, %ecx            /* Clear Hypervisor Present */
1:
    /* Filter 2: Hypervisor Range (0x40000000 - 0x4FFFFFFF) */
    mov %rbp, %r11
    shr $28, %r11
    cmp $4, %r11             /* If high nibble is 4, it's 0x40000000+ */
    jne 2f
    xor %eax, %eax
    xor %ebx, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
2:
    /* Write back results to guest structures */
    mov %rax, 0x5a8(%r14)    /* vmcb->save.rax */
    mov 0x10(%rsp), %r8      /* Remember: we pushed 2 regs, so regs_ptr is now at 16(%rsp) */
    mov %rbx, 0x00(%r8)      /* regs->rbx (wait, guest_regs starts with RBX!) */
    mov %rcx, 0x08(%r8)      /* regs->rcx */
    mov %rdx, 0x10(%r8)      /* regs->rdx */

    /* Restore HOST non-volatile registers */
    pop %rbp
    pop %rbx

    /* Advance Guest RIP! 
       vmcb->save.rip = vmcb->control.next_rip 
       offset 0x578 = rip, 0xD8 = next_rip */
    mov 0xD8(%r14), %r8
    mov %r8, 0x578(%r14)

    /* Back to the Matrix natively without touching C stack! */
    MACRO_FAST_VMRUN

    .align 64

.Lcheck_msr:
    /* Phase 29 T3: MSR Fast Path
       exit_info_1 & 1 == 0 means RDMSR. == 1 means WRMSR.
       We only optimize RDMSR. WRMSR falls back to C. */
    mov 0x78(%r14), %rax        /* exit_info_1 */
    test $1, %al
    jnz .Lslow_path             /* WRMSR -> C */

    /* Check MSR index in Guest ECX (still in %rcx) */
    cmp $0x10, %ecx
    je .Lnative_rdmsr
    
    /* Unsupported MSR -> C */
    jmp .Lslow_path

.Lnative_rdmsr:
    /* Save host RCX just in case, though rdmsr only needs ECX (which has the correct Guest MSR index) */
    push %rcx
    
    /* Execute native RDMSR on host. Outputs to %eax, %edx */
    rdmsr

    /* If it was TSC (0x10), we MUST add VMCB's tsc_offset! */
    pop %rcx
    cmp $0x10, %ecx
    jne 1f
    
    /* Combine EDX:EAX into RAX */
    shl $32, %rdx
    or %rax, %rdx
    /* RDX now holds full 64-bit TSC. Add tsc_offset */
    add 0x50(%r14), %rdx
    /* Split back to EAX and EDX */
    mov %rdx, %rax
    shr $32, %rdx
1:
    /* Write back results: Guest EAX in VMCB, Guest EDX in guest_regs.
       Wait, EAX/EDX writes will zero the upper 32-bits of the 64-bit registers anyway in 64-bit mode.
       Wait, RDMSR returns a 64-bit value, so the guest RAX and RDX should have upper 32 bits zeroed? 
       Yes, rdmsr returns 64-bit values into EDX:EAX. EDX gets top 32, EAX gets bottom 32.
       But the x86 manual says: "On 64-bit processors, the high-order 32 bits of RAX and RDX are cleared."
       So we must write EAX (zero-extended) to save.rax and EDX (zero-extended) to save RDX. */
    
    /* Zero extend EAX -> %rax */
    mov %eax, %eax
    mov %rax, 0x5A8(%r14)      /* vmcb->save.rax */

    /* Zero extend EDX -> %rdx */
    mov %edx, %edx
    mov 0(%rsp), %r8           /* %r8 = regs_ptr */
    mov %rdx, 0x10(%r8)        /* regs->rdx */

    /* Advance Guest RIP (skip over rdmsr which is 2 bytes, but next_rip handles this natively) */
    mov 0xD8(%r14), %r8        /* next_rip */
    mov %r8, 0x578(%r14)       /* save.rip */

    MACRO_FAST_VMRUN

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
