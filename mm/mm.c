
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mm/mm.h>
#include <mm/mmu_def.h>
#include <mm/buddy_allocator.h>
#include <mm/tzc400.h>
#include <common/def.h>

uint64_t current_cpu_stack_sps[PHYSICAL_CORE_NUM] = {0};

extern void activate_mmu(void);

uint64_t _boot_pt_l0_0[BIT(L0_BITS)] __attribute__((__aligned__(BIT(L0_PTP_BITS))));
uint64_t _boot_pt_l1_0[BIT(L1_BITS)] __attribute__((__aligned__(BIT(L1_PTP_BITS))));
uint64_t _boot_pt_l2_0[BIT(L2_BITS)] __attribute__((__aligned__(BIT(L2_PTP_BITS))));

static void init_percpu_stack(void) {
    int i = 0;
    for (; i < PHYSICAL_CORE_NUM; i++) {
        uint64_t stack_page = (uint64_t)bd_alloc(PAGE_SIZE, 12);
        current_cpu_stack_sps[i] = stack_page + PAGE_SIZE;
    }
}

extern void activate_mmu(void);


vaddr_t phys_to_virt(paddr_t phys) {
    return (vaddr_t)phys;
}

paddr_t virt_to_phys(vaddr_t virt) {
    return (paddr_t)virt;
}

static void initialize_boot_page_table(void) {
	uint64_t i, j;

	vaddr_t first_vaddr = KERNEL_VADDR;
	paddr_t first_paddr = 0;

	printf("[BOOT] init boot page table: first_vaddr=0x%lx first_paddr=0x%lx\r\n",
	       first_vaddr, first_paddr);

    memset(_boot_pt_l0_0, 0, sizeof(uint64_t) * BIT(L0_BITS));
    memset(_boot_pt_l1_0, 0, sizeof(uint64_t) * BIT(L1_BITS));
	_boot_pt_l0_0[0] = ((uintptr_t) _boot_pt_l1_0) | BIT(1) | BIT(0);
	_boot_pt_l1_0[0] = ((uintptr_t) _boot_pt_l2_0) | BIT(1) | BIT(0);

    for (j = GET_L2_INDEX(0x6000000); j < GET_L2_INDEX(0x8000000); j++) {
        _boot_pt_l2_0[j] = (j << HP_2M_BLOCK_SHIFT)
                | BIT(10)	/* bit[10]: access flag */
                | (3 << 8)  /* bit[9-8]: inner shareable */
                /* bit[7-6] data access permission bit */
                /* bit[5] non-secure bit */
                | (4 << 2)	/* bit[4-2]: MT_NORMAL */
                            /* bit[1]: block (0) table (1) */
                | BIT(0);	/* bit[0]: valid */
    }
    // for uart 0x1c0a0000
    j = GET_L2_INDEX(0x1c000000);
    _boot_pt_l2_0[j] = (j << HP_2M_BLOCK_SHIFT)
             | BIT(10)	/* bit[10]: access flag */
             | (3 << 8)  /* bit[9-8]: inner shareable */
             /* bit[7-6] data access permission bit */
             /* bit[5] non-secure bit */
             | (0 << 2)	/* bit[4-2]: MT_DEVICE_nGnRnE */
                         /* bit[1]: block (0) table (1) */
             | BIT(0);	/* bit[0]: valid */
   
    // for tcz 2a4a0000
    j = GET_L2_INDEX(0x2a4a0000);
    _boot_pt_l2_0[j] = (j << HP_2M_BLOCK_SHIFT)
             | BIT(10)	/* bit[10]: access flag */
             | (3 << 8)  /* bit[9-8]: inner shareable */
             /* bit[7-6] data access permission bit */
             /* bit[5] non-secure bit */
             | (0 << 2)	/* bit[4-2]: MT_DEVICE_nGnRnE */
                         /* bit[1]: block (0) table (1) */
             | BIT(0);	/* bit[0]: valid */

    // linux mem region
    for (i = GET_L1_INDEX(0x80000000); i < GET_L1_INDEX(0x100000000); i++) {
        _boot_pt_l1_0[i] = (i << HP_1G_BLOCK_SHIFT)
            | BIT(10)	/* bit[10]: access flag */
            | (3 << 8)  /* bit[9-8]: inner shareable */
                        /* bit[7-6] data access permission bit */
            | (1 << 5)  /* bit[5] non-secure bit */
            | (4 << 2)	/* bit[4-2]: MT_NORMAL */
                        /* bit[1]: block (0) table (1) */
            | BIT(0);	/* bit[0]: valid */
    }

    // linux split cma region
    for (i = GET_L1_INDEX(0x880000000); i < GET_L1_INDEX(0x8c0000000); i++) {
        _boot_pt_l1_0[i] = (i << HP_1G_BLOCK_SHIFT)
            | BIT(10)	/* bit[10]: access flag */
            | (3 << 8)  /* bit[9-8]: inner shareable */
                        /* bit[7-6] data access permission bit */
            | (0 << 5)  /* bit[5] non-secure bit */
            | (4 << 2)	/* bit[4-2]: MT_NORMAL */
                        /* bit[1]: block (0) table (1) */
            | BIT(0);	/* bit[0]: valid */
    }

    // linux mem region
    for (i = GET_L1_INDEX(0x8c0000000); i < GET_L1_INDEX(0x900000000); i++) {
        _boot_pt_l1_0[i] = (i << HP_1G_BLOCK_SHIFT)
            | BIT(10)	/* bit[10]: access flag */
            | (3 << 8)  /* bit[9-8]: inner shareable */
                        /* bit[7-6] data access permission bit */
            | (1 << 5)  /* bit[5] non-secure bit */
            | (4 << 2)	/* bit[4-2]: MT_NORMAL */
                        /* bit[1]: block (0) table (1) */
            | BIT(0);	/* bit[0]: valid */
    }

    // normal memory linux not known
    for (i = GET_L1_INDEX(0x900000000); i < GET_L1_INDEX(0x940000000); i++) {
        _boot_pt_l1_0[i] = (i << HP_1G_BLOCK_SHIFT)
            | BIT(10)	/* bit[10]: access flag */
            | (3 << 8)  /* bit[9-8]: inner shareable */
                        /* bit[7-6] data access permission bit */
            | (1 << 5)  /* bit[5] non-secure bit */
            | (4 << 2)	/* bit[4-2]: MT_NORMAL */
                        /* bit[1]: block (0) table (1) */
            | BIT(0);	/* bit[0]: valid */
    }
}

void mm_primary_init(void) {
    initialize_boot_page_table();
    activate_mmu();
    bd_init();
    tzc400_init();
    init_percpu_stack();
}

void mm_secondary_init(void) {
    activate_mmu();
}
