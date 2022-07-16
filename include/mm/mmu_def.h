#pragma once

#define KERNEL_VADDR        0xffffff0000000000

#define BIT(x)             (1UL << (x))
#define MASK(n)             (BIT(n) - 1)

#define HP_1G_BLOCK_SHIFT   30
#define HP_2M_BLOCK_SHIFT   21

#define PAGE_SHIFT          12
#define PAGE_MASK           ((1UL << PAGE_SHIFT) - 1)
#define PAGE_SIZE           4096

#define L0_BITS             9
#define L0_ENTRY_BITS       3
#define L0_PTP_BITS         13

#define L1_BITS             9
#define L1_ENTRY_BITS       3
#define L1_PTP_BITS         12

#define L2_BITS             9
#define L2_ENTRY_BITS       3
#define L2_PTP_BITS         12

#define L3_BITS             9
#define L3_ENTRY_BITS       3
#define L3_PTP_BITS         12

#define GET_L0_INDEX(x)        \
	(((x) >> (HP_2M_BLOCK_SHIFT + L1_BITS + L2_BITS)) & MASK(L0_BITS))
#define GET_L1_INDEX(x)        \
	(((x) >> (HP_2M_BLOCK_SHIFT + L2_BITS)) & MASK(L1_BITS))
#define GET_L2_INDEX(x)        \
	(((x) >> (HP_2M_BLOCK_SHIFT)) & MASK(L2_BITS))

