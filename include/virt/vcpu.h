#pragma once

#include <virt/vm.h>
#include <stdint.h>
#include <stddef.h>

enum vcpu_state {
    VCPU_INIT = 0,
    VCPU_READY,
    VCPU_TRAPPED,
    VCPU_RUNNING,
    VCPU_DESTROY,
};

struct gp_regs {
    unsigned long    x[31];
};

struct sys_regs {
	unsigned long	spsr;
	unsigned long	elr;
	unsigned long	sctlr;
    unsigned long   sp;
    unsigned long   sp_el0;
    unsigned long   esr;
    unsigned long   vbar;
    unsigned long   ttbr0;
    unsigned long   ttbr1;
    unsigned long   mair;
    unsigned long   amair;
    unsigned long   tcr;
    unsigned long   tpidr;
    unsigned long   tpidr_el0;
    unsigned long   tpidrro;
    unsigned long   actlr;
    unsigned long   mpidr;
    unsigned long   csselr;
    unsigned long   cpacr;
    unsigned long   afsr0;
    unsigned long   afsr1;
    unsigned long   far;
    unsigned long   contextidr;
    unsigned long   cntkctl;
    unsigned long   par;
    unsigned long   disr;
};

struct hyp_regs {
    unsigned long  hcr;
    unsigned long  esr;
    unsigned long  hpfar;
};

struct vcpu_ctx {
    struct gp_regs gp_regs;
    struct sys_regs sys_regs;
    struct hyp_regs hyp_regs;
};

struct s_visor_host_regs {
    struct gp_regs gp_regs;
};

struct thread_vector_table {
	unsigned int std_smc_entry;
	unsigned int fast_smc_entry;
	unsigned int cpu_on_entry;
	unsigned int cpu_off_entry;
	unsigned int cpu_resume_entry;
	unsigned int cpu_suspend_entry;
	unsigned int fiq_entry;
	unsigned int system_off_entry;
	unsigned int system_reset_entry;
};

struct kvm_decode {
    unsigned long rt;
    int sign_extend;
};

struct s_visor_vcpu {
    struct s_visor_vm *vm; // Point to vm struct the vcpu belongs to
    int vcpu_id; 
    int vcpu_state;
    struct vcpu_ctx current_vcpu_ctx;
    struct gp_regs* fastpath_ctx;

    /* KVM VM only */
    int is_s2pt_violation;
    int is_sync_trap;
    unsigned long fault_ipn;
    struct kvm_decode mmio_decode;
    int first_entry;
};

struct s_visor_state {
    struct s_visor_host_regs host_state;
    struct s_visor_vcpu* guest_state;
    struct s_visor_vm* current_vm;
};

#define DEFINE(sym, val) \
    asm volatile("\n.ascii \"->" #sym " %0 " #val "\"" : : "i" (val))

#define asmoffsetof(TYPE, MEMBER) ((unsigned long)&((TYPE *)0)->MEMBER)

extern uint64_t enter_guest(void);
