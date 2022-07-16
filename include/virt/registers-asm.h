#pragma once
#include <virt/asm-offsets.h>
#include <common/def.h>

.macro get_guest_gp_regs reg
        mrs     \reg, tpidr_el2
        add     \reg, \reg, #GUEST_STATE_OFFSET
        ldr     \reg, [\reg]
        add     \reg, \reg, #GUEST_CTX_OFFSET
        add     \reg, \reg, #GUEST_GP_REGS_OFFSET
.endm

.macro get_guest_sys_regs reg
        mrs     \reg, tpidr_el2
        add     \reg, \reg, #GUEST_STATE_OFFSET
        ldr     \reg, [\reg]
        add     \reg, \reg, #GUEST_CTX_OFFSET
        add     \reg, \reg, #GUEST_SYS_REGS_OFFSET
.endm

.macro get_guest_hyp_regs reg
        mrs     \reg, tpidr_el2
        add     \reg, \reg, #GUEST_STATE_OFFSET
        ldr     \reg, [\reg]
        add     \reg, \reg, #GUEST_CTX_OFFSET
        add     \reg, \reg, #GUEST_HYP_REGS_OFFSET
.endm

.macro get_guest_fastpath_gp_regs reg
		mrs     \reg, tpidr_el2
        add     \reg, \reg, #GUEST_STATE_OFFSET
        ldr     \reg, [\reg]
        add     \reg, \reg, #VCPU_CTX_OFFSET
		add     \reg, \reg, #FASTPATH_CTX_OFFSET
		ldr     \reg, [\reg]
.endm

.macro get_host_gp_regs reg
        mrs     \reg, tpidr_el2
        add     \reg, \reg, #HOST_STATE_OFFSET
        add     \reg, \reg, #HOST_GP_REGS_OFFSET
.endm

.macro save_callee_saved_gp_regs ctxt
	stp	x19, x20, [\ctxt, #CPU_XREG_OFFSET(19)]
	stp	x21, x22, [\ctxt, #CPU_XREG_OFFSET(21)]
	stp	x23, x24, [\ctxt, #CPU_XREG_OFFSET(23)]
	stp	x25, x26, [\ctxt, #CPU_XREG_OFFSET(25)]
	stp	x27, x28, [\ctxt, #CPU_XREG_OFFSET(27)]
	stp	x29, lr,  [\ctxt, #CPU_XREG_OFFSET(29)]
.endm

.macro restore_callee_saved_gp_regs ctxt
	ldp	x19, x20, [\ctxt, #CPU_XREG_OFFSET(19)]
	ldp	x21, x22, [\ctxt, #CPU_XREG_OFFSET(21)]
	ldp	x23, x24, [\ctxt, #CPU_XREG_OFFSET(23)]
	ldp	x25, x26, [\ctxt, #CPU_XREG_OFFSET(25)]
	ldp	x27, x28, [\ctxt, #CPU_XREG_OFFSET(27)]
	ldp	x29, lr,  [\ctxt, #CPU_XREG_OFFSET(29)]
.endm

.macro save_all_gp_regs ctxt
	stp	x2, x3,   [\ctxt, #CPU_XREG_OFFSET(2)]
	stp	x4, x5,   [\ctxt, #CPU_XREG_OFFSET(4)]
	stp	x6, x7,   [\ctxt, #CPU_XREG_OFFSET(6)]
	stp	x8, x9,   [\ctxt, #CPU_XREG_OFFSET(8)]
	stp	x10, x11, [\ctxt, #CPU_XREG_OFFSET(10)]
	stp	x12, x13, [\ctxt, #CPU_XREG_OFFSET(12)]
	stp	x14, x15, [\ctxt, #CPU_XREG_OFFSET(14)]
	stp	x16, x17, [\ctxt, #CPU_XREG_OFFSET(16)]
	str	x18,      [\ctxt, #CPU_XREG_OFFSET(18)]
	stp	x19, x20, [\ctxt, #CPU_XREG_OFFSET(19)]
	stp	x21, x22, [\ctxt, #CPU_XREG_OFFSET(21)]
	stp	x23, x24, [\ctxt, #CPU_XREG_OFFSET(23)]
	stp	x25, x26, [\ctxt, #CPU_XREG_OFFSET(25)]
	stp	x27, x28, [\ctxt, #CPU_XREG_OFFSET(27)]
	stp	x29, lr,  [\ctxt, #CPU_XREG_OFFSET(29)]
.endm

.macro restore_all_gp_regs ctxt
	ldp	x2, x3,   [\ctxt, #CPU_XREG_OFFSET(2)]
	ldp	x4, x5,   [\ctxt, #CPU_XREG_OFFSET(4)]
	ldp	x6, x7,   [\ctxt, #CPU_XREG_OFFSET(6)]
	ldp	x8, x9,   [\ctxt, #CPU_XREG_OFFSET(8)]
	ldp	x10, x11, [\ctxt, #CPU_XREG_OFFSET(10)]
	ldp	x12, x13, [\ctxt, #CPU_XREG_OFFSET(12)]
	ldp	x14, x15, [\ctxt, #CPU_XREG_OFFSET(14)]
	ldp	x16, x17, [\ctxt, #CPU_XREG_OFFSET(16)]
	ldr	x18,      [\ctxt, #CPU_XREG_OFFSET(18)]
	ldp	x19, x20, [\ctxt, #CPU_XREG_OFFSET(19)]
	ldp	x21, x22, [\ctxt, #CPU_XREG_OFFSET(21)]
	ldp	x23, x24, [\ctxt, #CPU_XREG_OFFSET(23)]
	ldp	x25, x26, [\ctxt, #CPU_XREG_OFFSET(25)]
	ldp	x27, x28, [\ctxt, #CPU_XREG_OFFSET(27)]
	ldp	x29, lr,  [\ctxt, #CPU_XREG_OFFSET(29)]
.endm

.macro save_guest_states tmp0, tmp1, tmp2
    // save gpr to local
    stp         \tmp0, \tmp1, [sp, #-16]! // save x0 and x1 to stack
    get_guest_gp_regs \tmp0
    save_all_gp_regs \tmp0
    ldp         \tmp1, \tmp2, [sp], #16 // restore x0, x1
    stp	        \tmp1, \tmp2, [\tmp0, #CPU_XREG_OFFSET(0)]
   
    // save el1 regs
    get_guest_sys_regs \tmp0
    mrs         \tmp1, spsr_el12 
    str	        \tmp1, [\tmp0, #SYS_SPSR_OFFSET]
    mrs         \tmp1, elr_el12
    str	        \tmp1, [\tmp0, #SYS_ELR_OFFSET]
    mrs         \tmp1, sctlr_el12
    str	        \tmp1, [\tmp0, #SYS_SCTLR_OFFSET]
    mrs         \tmp1, sp_el1
    str	        \tmp1, [\tmp0, #SYS_SP_OFFSET]
    mrs         \tmp1, sp_el0
    str	        \tmp1, [\tmp0, #SYS_SP_EL0_OFFSET]
    mrs         \tmp1, esr_el12
    str	        \tmp1, [\tmp0, #SYS_ESR_OFFSET]
    mrs         \tmp1, vbar_el12
    str	        \tmp1, [\tmp0, #SYS_VBAR_OFFSET]
    mrs         \tmp1, ttbr0_el12
    str	        \tmp1, [\tmp0, #SYS_TTBR0_OFFSET]
    mrs         \tmp1, ttbr1_el12
    str	        \tmp1, [\tmp0, #SYS_TTBR1_OFFSET]
    mrs         \tmp1, mair_el12
    str	        \tmp1, [\tmp0, #SYS_MAIR_OFFSET]
    mrs         \tmp1, amair_el12
    str	        \tmp1, [\tmp0, #SYS_AMAIR_OFFSET]
    mrs         \tmp1, tcr_el12
    str	        \tmp1, [\tmp0, #SYS_TCR_OFFSET]
    mrs         \tmp1, tpidr_el1
    str	        \tmp1, [\tmp0, #SYS_TPIDR_OFFSET]
    mrs         \tmp1, actlr_el1
    str	        \tmp1, [\tmp0, #SYS_ACTLR_OFFSET]
    mrs         \tmp1, tpidr_el0
    str	        \tmp1, [\tmp0, #SYS_TPIDR_EL0_OFFSET]
    mrs         \tmp1, tpidrro_el0
    str	        \tmp1, [\tmp0, #SYS_TPIDRRO_OFFSET]
    mrs         \tmp1, vmpidr_el2
    str	        \tmp1, [\tmp0, #SYS_MPIDR_OFFSET]
    mrs         \tmp1, csselr_el1
    str	        \tmp1, [\tmp0, #SYS_CSSELR_OFFSET]
    mrs         \tmp1, cpacr_el12
    str	        \tmp1, [\tmp0, #SYS_CPACR_OFFSET]
    mrs         \tmp1, afsr0_el12
    str	        \tmp1, [\tmp0, #SYS_AFSR0_OFFSET]
    mrs         \tmp1, afsr1_el12
    str	        \tmp1, [\tmp0, #SYS_AFSR1_OFFSET]
    mrs         \tmp1, far_el12
    str	        \tmp1, [\tmp0, #SYS_FAR_OFFSET]
    mrs         \tmp1, contextidr_el12
    str	        \tmp1, [\tmp0, #SYS_CONTEXTIDR_OFFSET]
    mrs         \tmp1, cntkctl_el12
    str	        \tmp1, [\tmp0, #SYS_CNTKCTL_OFFSET]
    mrs         \tmp1, par_el1
    str	        \tmp1, [\tmp0, #SYS_PAR_OFFSET]

    get_guest_hyp_regs \tmp0
    mrs         \tmp1, hcr_el2
    str         \tmp1, [\tmp0, #HYP_HCR_OFFSET]
    mrs         \tmp1, esr_el2
    str         \tmp1, [\tmp0, #HYP_ESR_OFFSET]
    mrs         \tmp1, hpfar_el2
    str         \tmp1, [\tmp0, #HYP_HPFAR_OFFSET]
.endm

.macro restore_guest_states tmp0, tmp1
    get_guest_sys_regs \tmp0
    ldr	        \tmp1, [\tmp0, #SYS_SPSR_OFFSET]
    msr         spsr_el12, \tmp1 
    ldr	        \tmp1, [\tmp0, #SYS_ELR_OFFSET]
    msr         elr_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_SCTLR_OFFSET]
    msr         sctlr_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_SP_OFFSET]
    msr         sp_el1, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_SP_EL0_OFFSET]
    msr         sp_el0, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_ESR_OFFSET]
    msr         esr_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_VBAR_OFFSET]
    msr         vbar_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_TTBR0_OFFSET]
    msr         ttbr0_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_TTBR1_OFFSET]
    msr         ttbr1_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_MAIR_OFFSET]
    msr         mair_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_AMAIR_OFFSET]
    msr         amair_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_TCR_OFFSET]
    msr         tcr_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_TPIDR_OFFSET]
    msr         tpidr_el1, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_ACTLR_OFFSET]
    msr         actlr_el1, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_TPIDR_EL0_OFFSET]
    msr         tpidr_el0, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_TPIDRRO_OFFSET]
    msr         tpidrro_el0, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_MPIDR_OFFSET]  // no MPIDR in el2
    msr         vmpidr_el2, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_CSSELR_OFFSET] // no CSSELR in el2
    msr         csselr_el1, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_CPACR_OFFSET]
    msr         cpacr_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_AFSR0_OFFSET]
    msr         afsr0_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_AFSR1_OFFSET]
    msr         afsr1_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_FAR_OFFSET]
    msr         far_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_CONTEXTIDR_OFFSET] // banked register NS and S for aarch32
    msr         contextidr_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_CNTKCTL_OFFSET]
    msr         cntkctl_el12, \tmp1
    ldr	        \tmp1, [\tmp0, #SYS_PAR_OFFSET] // for all el, banked register NS and S
    msr         par_el1, \tmp1
    isb

    get_guest_gp_regs \tmp0
    restore_all_gp_regs \tmp0
    ldp         \tmp0, \tmp1, [\tmp0, #CPU_XREG_OFFSET(0)]
.endm

.macro restore_host_states tmp0, tmp1
    get_host_gp_regs \tmp0
    restore_all_gp_regs \tmp0
    ldp         \tmp0, \tmp1, [\tmp0, #CPU_XREG_OFFSET(0)]
.endm
