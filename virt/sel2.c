#include <common/macro.h>
#include <virt/sel2.h>
#include <virt/stage2_mmu.h>
#include <virt/vcpu.h>
#include <timer.h>
#include <stdio.h>

extern void activate_stage2_mmu(void);
extern void enable_hyp_mode(void);

void virt_primary_init(void) {
    /* Turn on hypervisor related configuration */
    enable_hyp_mode();

    /* Initialize all VMs statically */
    init_vms();

    /* Turn on stage2 mmu for VMs */
    activate_stage2_mmu();
}

void virt_secondary_init(void) {
	/* Turn on hypervisor related configuration */
	enable_hyp_mode();
	
    /* Turn on stage2 mmu for VMs */
	activate_stage2_mmu();
}

void hyp_panic(void) {
    printf("[S-visor Panic]!!!!!\n");
    while(1)
        ;
}
