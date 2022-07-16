#pragma once

/*This file is generated. Please do not modify it!*/

#define GLOBAL_S_VISOR_STATE_SIZE 264 /* sizeof(struct s_visor_state) */
#define PER_CPU_STACK_SIZE 4096 /* 4096 */
#define HOST_STATE_OFFSET 0 /* asmoffsetof(struct s_visor_state, host_state) */
#define HOST_GP_REGS_OFFSET 0 /* asmoffsetof(struct s_visor_host_regs, gp_regs) */
#define GUEST_STATE_OFFSET 248 /* asmoffsetof(struct s_visor_state, guest_state) */
#define FASTPATH_CTX_OFFSET 496 /* asmoffsetof(struct s_visor_vcpu, fastpath_ctx) */
#define GUEST_CTX_OFFSET 16 /* asmoffsetof(struct s_visor_vcpu, current_vcpu_ctx) */
#define GUEST_GP_REGS_OFFSET 0 /* asmoffsetof(struct vcpu_ctx, gp_regs) */
#define GUEST_SYS_REGS_OFFSET 248 /* asmoffsetof(struct vcpu_ctx, sys_regs) */
#define SYS_SPSR_OFFSET 0 /* asmoffsetof(struct sys_regs, spsr) */
#define SYS_ELR_OFFSET 8 /* asmoffsetof(struct sys_regs, elr) */
#define SYS_SCTLR_OFFSET 16 /* asmoffsetof(struct sys_regs, sctlr) */
#define SYS_SP_OFFSET 24 /* asmoffsetof(struct sys_regs, sp) */
#define SYS_SP_EL0_OFFSET 32 /* asmoffsetof(struct sys_regs, sp_el0) */
#define SYS_ESR_OFFSET 40 /* asmoffsetof(struct sys_regs, esr) */
#define SYS_VBAR_OFFSET 48 /* asmoffsetof(struct sys_regs, vbar) */
#define SYS_TTBR0_OFFSET 56 /* asmoffsetof(struct sys_regs, ttbr0) */
#define SYS_TTBR1_OFFSET 64 /* asmoffsetof(struct sys_regs, ttbr1) */
#define SYS_MAIR_OFFSET 72 /* asmoffsetof(struct sys_regs, mair) */
#define SYS_AMAIR_OFFSET 80 /* asmoffsetof(struct sys_regs, amair) */
#define SYS_TCR_OFFSET 88 /* asmoffsetof(struct sys_regs, tcr) */
#define SYS_TPIDR_OFFSET 96 /* asmoffsetof(struct sys_regs, tpidr) */
#define SYS_ACTLR_OFFSET 120 /* asmoffsetof(struct sys_regs, actlr) */
#define SYS_TPIDR_EL0_OFFSET 104 /* asmoffsetof(struct sys_regs, tpidr_el0) */
#define SYS_TPIDRRO_OFFSET 112 /* asmoffsetof(struct sys_regs, tpidrro) */
#define SYS_MPIDR_OFFSET 128 /* asmoffsetof(struct sys_regs, mpidr) */
#define SYS_CSSELR_OFFSET 136 /* asmoffsetof(struct sys_regs, csselr) */
#define SYS_CPACR_OFFSET 144 /* asmoffsetof(struct sys_regs, cpacr) */
#define SYS_AFSR0_OFFSET 152 /* asmoffsetof(struct sys_regs, afsr0) */
#define SYS_AFSR1_OFFSET 160 /* asmoffsetof(struct sys_regs, afsr1) */
#define SYS_FAR_OFFSET 168 /* asmoffsetof(struct sys_regs, far) */
#define SYS_CONTEXTIDR_OFFSET 176 /* asmoffsetof(struct sys_regs, contextidr) */
#define SYS_CNTKCTL_OFFSET 184 /* asmoffsetof(struct sys_regs, cntkctl) */
#define SYS_PAR_OFFSET 192 /* asmoffsetof(struct sys_regs, par) */
#define SYS_DISR_OFFSET 200 /* asmoffsetof(struct sys_regs, disr) */
#define GUEST_HYP_REGS_OFFSET 456 /* asmoffsetof(struct vcpu_ctx, hyp_regs) */
#define HYP_HCR_OFFSET 0 /* asmoffsetof(struct hyp_regs, hcr) */
#define HYP_ESR_OFFSET 8 /* asmoffsetof(struct hyp_regs, esr) */
#define HYP_HPFAR_OFFSET 16 /* asmoffsetof(struct hyp_regs, hpfar) */
