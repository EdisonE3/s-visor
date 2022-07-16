#include <virt/vcpu.h>
#include <common/def.h>

int main(void) {
    DEFINE(GLOBAL_S_VISOR_STATE_SIZE, sizeof(struct s_visor_state));
    DEFINE(PER_CPU_STACK_SIZE, 4096);
   
    DEFINE(HOST_STATE_OFFSET, asmoffsetof(struct s_visor_state, host_state));
    DEFINE(HOST_GP_REGS_OFFSET, asmoffsetof(struct s_visor_host_regs, gp_regs));
    DEFINE(GUEST_STATE_OFFSET, asmoffsetof(struct s_visor_state, guest_state));
    DEFINE(FASTPATH_CTX_OFFSET, asmoffsetof(struct s_visor_vcpu, fastpath_ctx));
    DEFINE(GUEST_CTX_OFFSET, asmoffsetof(struct s_visor_vcpu, current_vcpu_ctx));
    DEFINE(GUEST_GP_REGS_OFFSET, asmoffsetof(struct vcpu_ctx, gp_regs));
    DEFINE(GUEST_SYS_REGS_OFFSET, asmoffsetof(struct vcpu_ctx, sys_regs));
    DEFINE(SYS_SPSR_OFFSET, asmoffsetof(struct sys_regs, spsr));
    DEFINE(SYS_ELR_OFFSET, asmoffsetof(struct sys_regs, elr));
    DEFINE(SYS_SCTLR_OFFSET, asmoffsetof(struct sys_regs, sctlr));
    DEFINE(SYS_SP_OFFSET, asmoffsetof(struct sys_regs, sp));
    DEFINE(SYS_SP_EL0_OFFSET, asmoffsetof(struct sys_regs, sp_el0));
    DEFINE(SYS_ESR_OFFSET, asmoffsetof(struct sys_regs, esr));
    DEFINE(SYS_VBAR_OFFSET, asmoffsetof(struct sys_regs, vbar));
    DEFINE(SYS_TTBR0_OFFSET, asmoffsetof(struct sys_regs, ttbr0));
    DEFINE(SYS_TTBR1_OFFSET, asmoffsetof(struct sys_regs, ttbr1));
    DEFINE(SYS_MAIR_OFFSET, asmoffsetof(struct sys_regs, mair));
    DEFINE(SYS_AMAIR_OFFSET, asmoffsetof(struct sys_regs, amair));
    DEFINE(SYS_TCR_OFFSET, asmoffsetof(struct sys_regs, tcr));
    DEFINE(SYS_TPIDR_OFFSET, asmoffsetof(struct sys_regs, tpidr));
    DEFINE(SYS_ACTLR_OFFSET, asmoffsetof(struct sys_regs, actlr));
    DEFINE(SYS_TPIDR_EL0_OFFSET, asmoffsetof(struct sys_regs, tpidr_el0));
    DEFINE(SYS_TPIDRRO_OFFSET, asmoffsetof(struct sys_regs, tpidrro));
    DEFINE(SYS_MPIDR_OFFSET, asmoffsetof(struct sys_regs, mpidr));
    DEFINE(SYS_CSSELR_OFFSET, asmoffsetof(struct sys_regs, csselr));
    DEFINE(SYS_CPACR_OFFSET, asmoffsetof(struct sys_regs, cpacr));
    DEFINE(SYS_AFSR0_OFFSET, asmoffsetof(struct sys_regs, afsr0));
    DEFINE(SYS_AFSR1_OFFSET, asmoffsetof(struct sys_regs, afsr1));
    DEFINE(SYS_FAR_OFFSET, asmoffsetof(struct sys_regs, far));
    DEFINE(SYS_CONTEXTIDR_OFFSET, asmoffsetof(struct sys_regs, contextidr));
    DEFINE(SYS_CNTKCTL_OFFSET, asmoffsetof(struct sys_regs, cntkctl));
    DEFINE(SYS_PAR_OFFSET, asmoffsetof(struct sys_regs, par));
    DEFINE(SYS_DISR_OFFSET, asmoffsetof(struct sys_regs, disr));
    DEFINE(GUEST_HYP_REGS_OFFSET, asmoffsetof(struct vcpu_ctx, hyp_regs));
    DEFINE(HYP_HCR_OFFSET, asmoffsetof(struct hyp_regs, hcr));
    DEFINE(HYP_ESR_OFFSET, asmoffsetof(struct hyp_regs, esr));
    DEFINE(HYP_HPFAR_OFFSET, asmoffsetof(struct hyp_regs, hpfar));
    return 0;
}

