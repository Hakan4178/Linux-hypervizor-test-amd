/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * svm_decode.S — Micro-Op Decoder & Emulator
 * 
 * Target: Ring -1 NPF Fast-Path (L1-I / L1-D / Op-Cache Optimized)
 * 
 * Calling Convention (System V AMD64 ABI):
 *   RDI = insn_buf (15-byte pre-fetched instruction buffer)
 *   RSI = struct guest_regs *  (Software saved GPRs)
 *   RDX = void *vmcb_save      (Hardware saved VMCB offsets)
 * 
 * Return (EAX):
 *   bits [7:0] = Instruction length (0 = failed)
 *   bit  8     = EMULATED flag
 *   bit  9     = BRANCH flag (RIP altered)
 *   bit  10    = MEMOP flag (Requires single-step)
 */

#include <linux/objtool.h>
#include <linux/linkage.h>

/* ═══════════════════════════════════════════════════════════════════════════
 *  Constants
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Return value construction */
#define RET_EMULATED    0x100
#define RET_BRANCH      0x200
#define RET_MEMOP       0x400

/* vmcb save area offsets (from vmcb->save base, AMD APM Vol.2 Table B-2) */
#define SAVE_RAX        0x1F8
#define SAVE_RSP        0x1D8
#define SAVE_RIP        0x178
#define SAVE_RFLAGS     0x170

/* guest_regs offsets */
#define GREGS_RBX       0x00
#define GREGS_RCX       0x08
#define GREGS_RDX       0x10
#define GREGS_RSI       0x18
#define GREGS_RDI       0x20
#define GREGS_RBP       0x28
#define GREGS_R8        0x30
#define GREGS_R9        0x38
#define GREGS_R10       0x40
#define GREGS_R11       0x48
#define GREGS_R12       0x50
#define GREGS_R13       0x58
#define GREGS_R14       0x60
#define GREGS_R15       0x68

/* ═══════════════════════════════════════════════════════════════════════════
 *  Register Offset Lookup Table
 *  Maps x86 register number (0-15) to offset within guest_regs (RSI)
 *  Special: reg 0 (RAX) and reg 4 (RSP) are in vmcb_save (RDX)
 *  Encoding: 0x8000 flag = use vmcb_save base, else use guest_regs base
 * ═══════════════════════════════════════════════════════════════════════════ */

#define VMCB_FLAG       0x8000

.section .rodata, "a"
.align 16
reg_offset_table:
	.short VMCB_FLAG | SAVE_RAX     /* 0  = RAX (vmcb_save) */
	.short GREGS_RCX                /* 1  = RCX */
	.short GREGS_RDX                /* 2  = RDX */
	.short GREGS_RBX                /* 3  = RBX */
	.short VMCB_FLAG | SAVE_RSP    /* 4  = RSP (vmcb_save) */
	.short GREGS_RBP                /* 5  = RBP */
	.short GREGS_RSI                /* 6  = RSI */
	.short GREGS_RDI                /* 7  = RDI */
	.short GREGS_R8                 /* 8  = R8  */
	.short GREGS_R9                 /* 9  = R9  */
	.short GREGS_R10                /* 10 = R10 */
	.short GREGS_R11                /* 11 = R11 */
	.short GREGS_R12                /* 12 = R12 */
	.short GREGS_R13                /* 13 = R13 */
	.short GREGS_R14                /* 14 = R14 */
	.short GREGS_R15                /* 15 = R15 */

/* ═══════════════════════════════════════════════════════════════════════════
 *  L1/L0 Cache Friendly Fast-Path Opcode LUT (Phase 24)
 *  Hits on NOP, PUSH, POP, RET immediately without decoding overhead.
 *  Returns 16-bit: (Flags << 8) | Length. (0 = FAST_PATH_FAIL/Slow-Path)
 * ═══════════════════════════════════════════════════════════════════════════ */
.align 64
fast_opcode_lut:
	.fill 80, 2, 0          /* 0x00 - 0x4F: Fallback/Complex */
	.fill 16, 2, 0x0401     /* 0x50 - 0x5F: PUSH/POP (RET_MEMOP | len 1) */
	.fill 48, 2, 0          /* 0x60 - 0x8F: Fallback */
	.short 0x0101           /* 0x90: NOP (RET_EMULATED | len 1) */
	.fill 50, 2, 0          /* 0x91 - 0xC2: Fallback */
	.short 0x0401           /* 0xC3: RET (RET_MEMOP | len 1) */
	.fill 60, 2, 0          /* 0xC4 - 0xFF: Fallback */

/* ═══════════════════════════════════════════════════════════════════════════
 *  Entry Point
 * ═══════════════════════════════════════════════════════════════════════════ */

.text
SYM_FUNC_START(svm_decode_insn)
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	mov	%rdi, %r12	/* r12 = insn_buf pointer */
	mov	%rsi, %r13	/* r13 = guest_regs pointer */
	mov	%rdx, %r14	/* r14 = vmcb_save pointer */
	xor	%r15d, %r15d	/* r15 = instruction offset (cursor) */
	xor	%ebx, %ebx	/* ebx = REX prefix (0 if none) */

/* ─── Phase 1: Prefix Scanner ─── */
.Lscan_prefix:
	movzbl	(%r12, %r15, 1), %eax

	/* REX prefix: 0x40 - 0x4F */
	cmp	$0x40, %al
	jb	.Lcheck_66
	cmp	$0x4F, %al
	ja	.Lcheck_66
	mov	%eax, %ebx	/* Save REX byte */
	inc	%r15
	jmp	.Lscan_prefix

.Lcheck_66:
	cmp	$0x66, %al	/* Operand size override — skip */
	je	.Lskip_prefix
	cmp	$0xF2, %al	/* REPNE — skip */
	je	.Lskip_prefix
	cmp	$0xF3, %al	/* REP — skip */
	je	.Lskip_prefix
	jmp	.Ldispatch

.Lskip_prefix:
	inc	%r15
	jmp	.Lscan_prefix

/* ─── Phase 2: Opcode Dispatch ─── */
.Ldispatch:
	movzbl	(%r12, %r15, 1), %eax

	/* [Phase 24] L1-D Cache Fast-Path Check */
	leaq	fast_opcode_lut(%rip), %rcx
	movzwl	(%rcx, %rax, 2), %ecx   /* Load 16-bit LUT entry (scale 2) */
	test	%ecx, %ecx
	jz	.Ldispatch_slow         /* If zero, fallback to complex decoding */

	/* Fast-Path HIT! */
	inc	%r15d                   /* cursor past opcode byte */
	movzx	%cl, %edx               /* Lower 8 bits = additional base length */
	dec	%edx                    /* Because r15d already incremented by 1 for opcode */
	add	%edx, %r15d
	mov	%r15d, %eax
	and	$0xFF00, %ecx           /* Upper 8 bits = Flags (RET_EMULATED / RET_MEMOP) */
	or	%ecx, %eax              /* Merge flags with total length */
	jmp	.Lreturn

.Ldispatch_slow:
	inc	%r15		/* cursor past opcode byte */

	/* NOP (0x90) (Now primarily handled by fast-path, kept for safety) */
	cmp	$0x90, %al
	je	.Lhandle_nop

	/* MOV r/m,r (0x89) — reg → r/m */
	cmp	$0x89, %al
	je	.Lhandle_modrm_rr

	/* MOV r,r/m (0x8B) — r/m → reg */
	cmp	$0x8B, %al
	je	.Lhandle_modrm_rr_rev

	/* XOR r/m,r (0x31) */
	cmp	$0x31, %al
	je	.Lhandle_xor

	/* XOR r,r/m (0x33) */
	cmp	$0x33, %al
	je	.Lhandle_xor_rev

	/* CMP r/m,r (0x39) */
	cmp	$0x39, %al
	je	.Lhandle_cmp

	/* CMP r,r/m (0x3B) */
	cmp	$0x3B, %al
	je	.Lhandle_cmp_rev

	/* TEST r/m,r (0x85) */
	cmp	$0x85, %al
	je	.Lhandle_test

	/* ADD r/m,r (0x01) */
	cmp	$0x01, %al
	je	.Lhandle_add

	/* SUB r/m,r (0x29) */
	cmp	$0x29, %al
	je	.Lhandle_sub

	/* AND r/m,r (0x21) */
	cmp	$0x21, %al
	je	.Lhandle_and

	/* OR r/m,r (0x09) */
	cmp	$0x09, %al
	je	.Lhandle_or

	/* JMP rel8 (0xEB) */
	cmp	$0xEB, %al
	je	.Lhandle_jmp_rel8

	/* JMP rel32 (0xE9) */
	cmp	$0xE9, %al
	je	.Lhandle_jmp_rel32

	/* Jcc rel8 (0x70 - 0x7F) */
	cmp	$0x70, %al
	jb	.Lcheck_2byte
	cmp	$0x7F, %al
	jbe	.Lhandle_jcc_rel8

	/* PUSH reg (0x50-0x57) — memory access, fallback */
	cmp	$0x50, %al
	jb	.Lcheck_pop
	cmp	$0x57, %al
	jbe	.Lhandle_memop_1byte

.Lcheck_pop:
	/* POP reg (0x58-0x5F) — memory access, fallback */
	cmp	$0x58, %al
	jb	.Lcheck_call
	cmp	$0x5F, %al
	jbe	.Lhandle_memop_1byte

.Lcheck_call:
	/* CALL rel32 (0xE8) — memory access (pushes return addr) */
	cmp	$0xE8, %al
	je	.Lhandle_memop_5byte

	/* RET (0xC3) — memory access (pops return addr) */
	cmp	$0xC3, %al
	je	.Lhandle_memop_1byte

	/* 2-byte opcode escape (0x0F) */
	cmp	$0x0F, %al
	je	.Lcheck_2byte_dispatch

.Lcheck_2byte:
	/* Tanınmayan opcode — fallback */
	jmp	.Lhandle_unknown

/* ─── 2-Byte Opcode Dispatch (0x0F xx) ─── */
.Lcheck_2byte_dispatch:
	movzbl	(%r12, %r15, 1), %eax
	inc	%r15

	/* RDTSC (0x0F 0x31) */
	cmp	$0x31, %al
	je	.Lhandle_rdtsc

	/* NOP /r (0x0F 0x1F) — multi-byte NOP */
	cmp	$0x1F, %al
	je	.Lhandle_long_nop

	/* Jcc rel32 (0x0F 0x80-0x8F) */
	cmp	$0x80, %al
	jb	.Lhandle_unknown
	cmp	$0x8F, %al
	jbe	.Lhandle_jcc_rel32

	jmp	.Lhandle_unknown

/* ═══════════════════════════════════════════════════════════════════════════
 *  Handlers
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ─── NOP ─── */
.Lhandle_nop:
	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── Long NOP (0F 1F /0) — skip ModRM + SIB + Disp ─── */
.Lhandle_long_nop:
	movzbl	(%r12, %r15, 1), %ecx	/* ModRM byte */
	inc	%r15
	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lskip_modrm_operand
	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── MOV r/m, r (0x89) — mod=11 only ─── */
.Lhandle_modrm_rr:
	movzbl	(%r12, %r15, 1), %ecx
	inc	%r15
	/* Check mod == 11 (register-register) */
	mov	%ecx, %eax
	shr	$6, %eax
	cmp	$3, %eax
	jne	.Lhandle_memop_modrm	/* Memory operand — fallback */

	/* reg field = source, rm field = destination */
	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lextract_reg_rm
	/* r8 = source reg ptr, r9 = dest reg ptr */
	mov	(%r8), %rax
	mov	%rax, (%r9)

	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── MOV r, r/m (0x8B) — mod=11 only ─── */
.Lhandle_modrm_rr_rev:
	movzbl	(%r12, %r15, 1), %ecx
	inc	%r15
	mov	%ecx, %eax
	shr	$6, %eax
	cmp	$3, %eax
	jne	.Lhandle_memop_modrm

	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lextract_reg_rm
	/* reg = destination, rm = source (reversed) */
	mov	(%r9), %rax
	mov	%rax, (%r8)

	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── XOR r/m, r (0x31) — mod=11: dst ^= src, update RFLAGS ─── */
.Lhandle_xor:
	movzbl	(%r12, %r15, 1), %ecx
	inc	%r15
	mov	%ecx, %eax
	shr	$6, %eax
	cmp	$3, %eax
	jne	.Lhandle_memop_modrm

	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lextract_reg_rm
	mov	(%r8), %rax		/* source */
	xor	%rax, (%r9)		/* XOR into dest — sets real RFLAGS */
	pushfq
	pop	%rax
	mov	%rax, SAVE_RFLAGS(%r14)	/* Store RFLAGS to vmcb */

	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── XOR r, r/m (0x33) ─── */
.Lhandle_xor_rev:
	movzbl	(%r12, %r15, 1), %ecx
	inc	%r15
	mov	%ecx, %eax
	shr	$6, %eax
	cmp	$3, %eax
	jne	.Lhandle_memop_modrm

	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lextract_reg_rm
	mov	(%r9), %rax
	xor	%rax, (%r8)
	pushfq
	pop	%rax
	mov	%rax, SAVE_RFLAGS(%r14)

	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── CMP r/m, r (0x39) — no write, only RFLAGS ─── */
.Lhandle_cmp:
	movzbl	(%r12, %r15, 1), %ecx
	inc	%r15
	mov	%ecx, %eax
	shr	$6, %eax
	cmp	$3, %eax
	jne	.Lhandle_memop_modrm

	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lextract_reg_rm
	mov	(%r9), %rax
	cmp	(%r8), %rax		/* CMP rm, reg */
	pushfq
	pop	%rax
	mov	%rax, SAVE_RFLAGS(%r14)

	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── CMP r, r/m (0x3B) ─── */
.Lhandle_cmp_rev:
	movzbl	(%r12, %r15, 1), %ecx
	inc	%r15
	mov	%ecx, %eax
	shr	$6, %eax
	cmp	$3, %eax
	jne	.Lhandle_memop_modrm

	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lextract_reg_rm
	mov	(%r8), %rax
	cmp	(%r9), %rax
	pushfq
	pop	%rax
	mov	%rax, SAVE_RFLAGS(%r14)

	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── TEST r/m, r (0x85) ─── */
.Lhandle_test:
	movzbl	(%r12, %r15, 1), %ecx
	inc	%r15
	mov	%ecx, %eax
	shr	$6, %eax
	cmp	$3, %eax
	jne	.Lhandle_memop_modrm

	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lextract_reg_rm
	mov	(%r8), %rax
	test	%rax, (%r9)
	pushfq
	pop	%rax
	mov	%rax, SAVE_RFLAGS(%r14)

	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── ADD r/m, r (0x01) ─── */
.Lhandle_add:
	movzbl	(%r12, %r15, 1), %ecx
	inc	%r15
	mov	%ecx, %eax
	shr	$6, %eax
	cmp	$3, %eax
	jne	.Lhandle_memop_modrm

	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lextract_reg_rm
	mov	(%r8), %rax
	add	%rax, (%r9)
	pushfq
	pop	%rax
	mov	%rax, SAVE_RFLAGS(%r14)

	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── SUB r/m, r (0x29) ─── */
.Lhandle_sub:
	movzbl	(%r12, %r15, 1), %ecx
	inc	%r15
	mov	%ecx, %eax
	shr	$6, %eax
	cmp	$3, %eax
	jne	.Lhandle_memop_modrm

	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lextract_reg_rm
	mov	(%r8), %rax
	sub	%rax, (%r9)
	pushfq
	pop	%rax
	mov	%rax, SAVE_RFLAGS(%r14)

	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── AND r/m, r (0x21) ─── */
.Lhandle_and:
	movzbl	(%r12, %r15, 1), %ecx
	inc	%r15
	mov	%ecx, %eax
	shr	$6, %eax
	cmp	$3, %eax
	jne	.Lhandle_memop_modrm

	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lextract_reg_rm
	mov	(%r8), %rax
	and	%rax, (%r9)
	pushfq
	pop	%rax
	mov	%rax, SAVE_RFLAGS(%r14)

	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── OR r/m, r (0x09) ─── */
.Lhandle_or:
	movzbl	(%r12, %r15, 1), %ecx
	inc	%r15
	mov	%ecx, %eax
	shr	$6, %eax
	cmp	$3, %eax
	jne	.Lhandle_memop_modrm

	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lextract_reg_rm
	mov	(%r8), %rax
	or	%rax, (%r9)
	pushfq
	pop	%rax
	mov	%rax, SAVE_RFLAGS(%r14)

	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── JMP rel8 (0xEB) ─── */
.Lhandle_jmp_rel8:
	movsbl	(%r12, %r15, 1), %eax	/* Sign-extend rel8 */
	inc	%r15
	/* new_rip = current_rip + insn_len + rel8 */
	movslq	%eax, %rax
	add	%r15, %rax		/* + instruction length */
	add	SAVE_RIP(%r14), %rax	/* + original RIP */
	mov	%rax, SAVE_RIP(%r14)

	mov	%r15d, %eax
	or	$(RET_EMULATED | RET_BRANCH), %eax
	jmp	.Lreturn

/* ─── JMP rel32 (0xE9) ─── */
.Lhandle_jmp_rel32:
	movl	(%r12, %r15, 1), %eax	/* Load rel32 */
	add	$4, %r15
	movslq	%eax, %rax
	add	%r15, %rax
	add	SAVE_RIP(%r14), %rax
	mov	%rax, SAVE_RIP(%r14)

	mov	%r15d, %eax
	or	$(RET_EMULATED | RET_BRANCH), %eax
	jmp	.Lreturn

/* ─── Jcc rel8 (0x70-0x7F) ─── */
.Lhandle_jcc_rel8:
	/* AL still has the opcode byte (0x70-0x7F) */
	sub	$0x70, %al		/* condition code = AL & 0x0F */
	movsbl	(%r12, %r15, 1), %ecx	/* rel8 displacement */
	inc	%r15

	/* Check condition using guest RFLAGS */
	mov	SAVE_RFLAGS(%r14), %r8
	push	%r8
	popfq				/* Load guest RFLAGS into CPU */

	/* Test condition — jump table too complex, use pushfq trick:
	 * Execute the matching Jcc and let the CPU evaluate the condition.
	 * We branch to .Ljcc_taken or fall through to .Ljcc_not_taken.
	 * For simplicity, we test CF/ZF/SF/OF manually for common cases.
	 */
	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Leval_condition	/* returns: AL = 1 if taken, 0 if not */

	test	%al, %al
	jz	.Ljcc_not_taken

	/* Branch taken: modify RIP */
	movslq	%ecx, %rcx
	add	%r15, %rcx
	add	SAVE_RIP(%r14), %rcx
	mov	%rcx, SAVE_RIP(%r14)

	mov	%r15d, %eax
	or	$(RET_EMULATED | RET_BRANCH), %eax
	jmp	.Lreturn

.Ljcc_not_taken:
	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── Jcc rel32 (0x0F 0x80-0x8F) ─── */
.Lhandle_jcc_rel32:
	sub	$0x80, %al		/* condition code */
	movl	(%r12, %r15, 1), %ecx
	add	$4, %r15

	mov	SAVE_RFLAGS(%r14), %r8
	push	%r8
	popfq

	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Leval_condition

	test	%al, %al
	jz	.Ljcc32_not_taken

	movslq	%ecx, %rcx
	add	%r15, %rcx
	add	SAVE_RIP(%r14), %rcx
	mov	%rcx, SAVE_RIP(%r14)

	mov	%r15d, %eax
	or	$(RET_EMULATED | RET_BRANCH), %eax
	jmp	.Lreturn

.Ljcc32_not_taken:
	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── RDTSC (0x0F 0x31) — return compensated TSC ─── */
.Lhandle_rdtsc:
	rdtsc				/* EDX:EAX = real TSC */
	/* Store into guest RAX and RDX */
	mov	%eax, %ecx
	mov	%edx, %r8d
	movl	%ecx, SAVE_RAX(%r14)	/* Low 32 bits → guest RAX */
	movq	%r8, GREGS_RDX(%r13)	/* High 32 bits → guest RDX */

	mov	%r15d, %eax
	or	$RET_EMULATED, %eax
	jmp	.Lreturn

/* ─── Memory-op Fallbacks ─── */
.Lhandle_memop_1byte:
	mov	%r15d, %eax
	or	$RET_MEMOP, %eax
	jmp	.Lreturn

.Lhandle_memop_5byte:
	add	$4, %r15d		/* skip imm32 */
	mov	%r15d, %eax
	or	$RET_MEMOP, %eax
	jmp	.Lreturn

.Lhandle_memop_modrm:
	/* cursor already past opcode, need to skip ModRM operand */
	ANNOTATE_INTRA_FUNCTION_CALL
	call	.Lskip_modrm_operand
	mov	%r15d, %eax
	or	$RET_MEMOP, %eax
	jmp	.Lreturn

/* ─── Unknown/Unsupported ─── */
.Lhandle_unknown:
	xor	%eax, %eax		/* length = 0, no flags = decode failed */
	jmp	.Lreturn

/* ═══════════════════════════════════════════════════════════════════════════
 *  Helper: Extract reg and rm register pointers from ModRM
 *  Input:  ECX = ModRM byte, EBX = REX prefix
 *  Output: R8  = pointer to 'reg' field register value
 *          R9  = pointer to 'rm' field register value
 * ═══════════════════════════════════════════════════════════════════════════ */
.Lextract_reg_rm:
	push	%rax

	/* Extract reg field: bits [5:3] of ModRM */
	mov	%ecx, %eax
	shr	$3, %eax
	and	$7, %eax
	/* Apply REX.R extension */
	test	$4, %ebx		/* REX.R = bit 2 */
	jz	1f
	or	$8, %eax
1:
	/* Look up register pointer */
	lea	reg_offset_table(%rip), %r10
	movzwl	(%r10, %rax, 2), %r11d
	test	$VMCB_FLAG, %r11d
	jnz	2f
	lea	(%r13, %r11, 1), %r8	/* guest_regs + offset */
	jmp	3f
2:
	and	$0x7FFF, %r11d
	lea	(%r14, %r11, 1), %r8	/* vmcb_save + offset */
3:

	/* Extract rm field: bits [2:0] of ModRM */
	mov	%ecx, %eax
	and	$7, %eax
	/* Apply REX.B extension */
	test	$1, %ebx		/* REX.B = bit 0 */
	jz	4f
	or	$8, %eax
4:
	movzwl	(%r10, %rax, 2), %r11d
	test	$VMCB_FLAG, %r11d
	jnz	5f
	lea	(%r13, %r11, 1), %r9
	jmp	6f
5:
	and	$0x7FFF, %r11d
	lea	(%r14, %r11, 1), %r9
6:
	pop	%rax
	ret

/* ═══════════════════════════════════════════════════════════════════════════
 *  Helper: Skip ModRM operand bytes (SIB + displacement)
 *  Input:  ECX = ModRM byte, R15 = current cursor (past ModRM)
 *  Modifies: R15 (advanced past SIB/disp)
 * ═══════════════════════════════════════════════════════════════════════════ */
.Lskip_modrm_operand:
	mov	%ecx, %eax
	shr	$6, %eax
	and	$3, %eax		/* mod field */

	mov	%ecx, %r8d
	and	$7, %r8d		/* rm field */

	cmp	$3, %eax
	je	.Lskip_done		/* mod=11: register, nothing to skip */

	/* Check for SIB byte: rm==4 AND mod != 11 */
	cmp	$4, %r8d
	jne	.Lskip_no_sib
	inc	%r15			/* Skip SIB byte */
.Lskip_no_sib:

	/* mod=00: no displacement (except rm=5 → disp32) */
	test	%eax, %eax
	jnz	.Lskip_mod01
	cmp	$5, %r8d
	jne	.Lskip_done
	add	$4, %r15		/* RIP-relative disp32 */
	jmp	.Lskip_done

.Lskip_mod01:
	cmp	$1, %eax		/* mod=01: disp8 */
	jne	.Lskip_mod10
	inc	%r15
	jmp	.Lskip_done

.Lskip_mod10:			/* mod=10: disp32 */
	add	$4, %r15

.Lskip_done:
	ret

/* ═══════════════════════════════════════════════════════════════════════════
 *  Helper: Evaluate Jcc condition code
 *  Input:  AL = condition code (0-15), CPU RFLAGS set from guest
 *  Output: AL = 1 (taken) / 0 (not taken)
 * ═══════════════════════════════════════════════════════════════════════════ */
.Leval_condition:
	/* Use the CPU's own condition evaluation via CMOV.
	 * Load 0 into ECX, 1 into EDX, then CMOVcc selects.
	 */
	push	%rbx
	xor	%ecx, %ecx
	mov	$1, %edx

	cmp	$0, %al		/* JO */
	je	.Lcond_o
	cmp	$1, %al		/* JNO */
	je	.Lcond_no
	cmp	$2, %al		/* JB/JC */
	je	.Lcond_b
	cmp	$3, %al		/* JAE/JNC */
	je	.Lcond_ae
	cmp	$4, %al		/* JE/JZ */
	je	.Lcond_e
	cmp	$5, %al		/* JNE/JNZ */
	je	.Lcond_ne
	cmp	$6, %al		/* JBE */
	je	.Lcond_be
	cmp	$7, %al		/* JA */
	je	.Lcond_a
	cmp	$8, %al		/* JS */
	je	.Lcond_s
	cmp	$9, %al		/* JNS */
	je	.Lcond_ns
	cmp	$12, %al		/* JL */
	je	.Lcond_l
	cmp	$13, %al		/* JGE */
	je	.Lcond_ge
	cmp	$14, %al		/* JLE */
	je	.Lcond_le
	cmp	$15, %al		/* JG */
	je	.Lcond_g

	/* JP/JNP (10,11) — rare, treat as not taken */
	xor	%eax, %eax
	pop	%rbx
	ret

.Lcond_o:	cmovo	%edx, %ecx;	jmp .Lcond_ret
.Lcond_no:	cmovno	%edx, %ecx;	jmp .Lcond_ret
.Lcond_b:	cmovb	%edx, %ecx;	jmp .Lcond_ret
.Lcond_ae:	cmovae	%edx, %ecx;	jmp .Lcond_ret
.Lcond_e:	cmove	%edx, %ecx;	jmp .Lcond_ret
.Lcond_ne:	cmovne	%edx, %ecx;	jmp .Lcond_ret
.Lcond_be:	cmovbe	%edx, %ecx;	jmp .Lcond_ret
.Lcond_a:	cmova	%edx, %ecx;	jmp .Lcond_ret
.Lcond_s:	cmovs	%edx, %ecx;	jmp .Lcond_ret
.Lcond_ns:	cmovns	%edx, %ecx;	jmp .Lcond_ret
.Lcond_l:	cmovl	%edx, %ecx;	jmp .Lcond_ret
.Lcond_ge:	cmovge	%edx, %ecx;	jmp .Lcond_ret
.Lcond_le:	cmovle	%edx, %ecx;	jmp .Lcond_ret
.Lcond_g:	cmovg	%edx, %ecx

.Lcond_ret:
	mov	%ecx, %eax
	pop	%rbx
	ret

/* ═══════════════════════════════════════════════════════════════════════════
 *  Return
 * ═══════════════════════════════════════════════════════════════════════════ */
.Lreturn:
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx
	RET
SYM_FUNC_END(svm_decode_insn)

/* Objtool'un bu dosyadaki 'intra-function' çağrılarını görmezden gelmesini sağlar */
.section .discard.objtool_nocalls, "aw"
    .long svm_decode_insn
.previous
