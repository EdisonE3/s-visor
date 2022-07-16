#include <s_visor.h>
#include <stdio.h>
#include <platform_def.h>
#include <platform.h>
#include <drivers/console.h>
#include <common/macro.h>
#include <mm/mm.h>
#include <mm/tzc400.h>
#include <virt/sel2.h>
#include <virt/vm.h>

#define VAL_EXTRACT_BITS(data, start, end) \
	((data >> start) & ((1ul << (end-start+1))-1))

uint64_t *shared_register_pages;
volatile int s_vring_init;
void init_big_hyp_lock();

int init_primary_core(void) {
	(void)console_init(PLAT_ARM_BL31_RUN_UART_BASE,
			   PLAT_ARM_BOOT_UART_CLK_IN_HZ, ARM_CONSOLE_BAUDRATE);

    /* Use virtual memory and initialize buddy and slab allocators*/
	mm_primary_init();

    /* Enable SEL2 virtualization function */
	virt_primary_init();

    shared_register_pages = NULL;

    s_vring_init = 0;

	return 0;
}

int init_secondary_core(void) {
    mm_secondary_init();

    virt_secondary_init();

    return 0;
}
