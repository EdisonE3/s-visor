#pragma once

#include <lib/utils_def.h>

#define MASK(n)             (BIT(n) - 1)

#define STAGE2_1G_BLOCK_SHIFT   30
#define STAGE2_2M_BLOCK_SHIFT   21

#define STAGE2_L0_BITS             9
#define STAGE2_L0_ENTRY_BITS       3
#define STAGE2_L0_PTP_BITS         12

#define STAGE2_L1_BITS             9
#define STAGE2_L1_ENTRY_BITS       3
#define STAGE2_L1_PTP_BITS         13

#define STAGE2_L2_BITS             9
#define STAGE2_L2_ENTRY_BITS       3
#define STAGE2_L2_PTP_BITS         12

#define STAGE2_L3_BITS             9
#define STAGE2_L3_ENTRY_BITS       3
#define STAGE2_L3_PTP_BITS         12

#define GET_STAGE2_L0_INDEX(x)        \
	(((x) >> (STAGE2_2M_BLOCK_SHIFT + STAGE2_L1_BITS + STAGE2_L2_BITS)) & MASK(STAGE2_L0_BITS))
#define GET_STAGE2_L1_INDEX(x)        \
	(((x) >> (STAGE2_2M_BLOCK_SHIFT + STAGE2_L2_BITS)) & MASK(STAGE2_L1_BITS))
#define GET_STAGE2_L2_INDEX(x)        \
	(((x) >> (STAGE2_2M_BLOCK_SHIFT)) & MASK(STAGE2_L2_BITS))

#define VSTCR_EL2_SA                BIT(30)  /* Secure stage 2 translation output address space */  
#define VSTCR_EL2_SW                BIT(31)  /* Secure stage 2 translation address space */  

#define HCR_EL2_MIOCNCE             BIT(38)   /* Mismatched inner/outer cacheable non-coherency enable For EL1&0 */  
#define HCR_SEL2_TEA		        BIT(37)   /* Route synchronous external abort exceptions to EL2 */
#define HCR_SEL2_TERR	            BIT(36)   /* Trap error record access to EL2 */
#define HCR_SEL2_TLOR	            BIT(35)   /* Trap LOR registers */ 
#define HCR_SEL2_E2H	        	BIT(34)   /* EL2 host: whether OS is running in EL2 */
#define HCR_SEL2_ID	                BIT(33)   /* Stage 2 instruction access cacheability disable */
#define HCR_SEL2_CD	            	BIT(32)   /* Stage 2 data access cacheability disable */
#define HCR_SEL2_RW		            BIT(31)   /* Execution state control for lower exception levels */
#define HCR_SEL2_TRVM	            BIT(30)   /* Trap reads of virtual memory controls */
#define HCR_SEL2_HCD		        BIT(29)   /* HVC instruction diable */
#define HCR_SEL2_TDZ		        BIT(28)   /* Trap DC ZVA instrucitons */
#define HCR_SEL2_TGE		        BIT(27)   /* Trap general exceptions from EL0 */
#define HCR_SEL2_TVM		        BIT(26)   /* Trap writes of virtual memory controls */
#define HCR_SEL2_TTLB	            BIT(25)   /* Trap TLB maintenance instructions */
#define HCR_SEL2_TPU		        BIT(24)   /* Trap cache maintenance instructions that operate to the point of unification */
#define HCR_SEL2_TPC		        BIT(23)   /* Trap data or unified cache maintenance instructions that operate to the point of coherency */
#define HCR_SEL2_TSW		        BIT(22)   /* Trap data or unified cache maintenance instructions that operate by Set/Way */
#define HCR_SEL2_TAC		        BIT(21)   /* Trap Auxiliary Control Registers */
#define HCR_SEL2_TIDCP	            BIT(20)
#define HCR_SEL2_TSC	            BIT(19)   /* Trap SMC instructions */
#define HCR_SEL2_TID3	            BIT(18)   /* Trap ID group 3 */
#define HCR_SEL2_TID2	            BIT(17)   /* Trap ID group 2 */
#define HCR_SEL2_TID1	            BIT(16)   /* Trap ID group 1 */
#define HCR_SEL2_TID0	            BIT(15)   /* Trap ID group 0 */
#define HCR_SEL2_TWE	            BIT(14)   /* Traps EL0 and EL1 execution of WFE instructions to EL2, from both Execution states. */
#define HCR_SEL2_TWI	            BIT(13)   /* Traps EL0 and EL1 execution of WFI instructions to EL2, from both Execution states. */
#define HCR_SEL2_DC		            BIT(12)  
#define HCR_SEL2_BSU	            (3 << 10) /* Barrier Shareability upgrade */
#define HCR_SEL2_BSU_IS	            BIT(10) 
#define HCR_SEL2_FB		            BIT(9)    /* Force broadcast */
#define HCR_SEL2_VSE	            BIT(8)    /* Virtual SError interrupt */ 
#define HCR_SEL2_VI		            BIT(7)    /* Virtual IRQ Interrupt */
#define HCR_SEL2_VF		            BIT(6)    /* Virtual FIQ Interrupt */
#define HCR_SEL2_AMO	            BIT(5)    /* Physical SError Interrupt routing */
#define HCR_SEL2_IMO	            BIT(4)    /* Physical IRQ Routing */
#define HCR_SEL2_FMO	            BIT(3)    /* Physical FIQ Routing */
#define HCR_SEL2_PTW	            BIT(2)    /* Protected Table Walk */
#define HCR_SEL2_SWIO	            BIT(1)    /* Set/Way Invalidation Override */
#define HCR_SEL2_VM		            BIT(0)    /* Virtualization enable */

#define HCR_TEST_GUEST_FLAGS (HCR_SEL2_VM | HCR_SEL2_RW)


/* VTCR_EL2 Registers bits */
#define VTCR_RES1              ((1UL << 31))
#define VTCR_EL2_T0SZ(x)       ((64 - (x)))
#define VTCR_SL0_L2            ((0 << 6))
#define VTCR_SL0_L1            ((1 << 6))
#define VTCR_SL0_L0            ((2 << 6))
#define VTCR_IRGN0_WBWC        ((1 << 8))
#define VTCR_IRGN_NC           ((0 << 8))
#define VTCR_IRGN_WBWA         ((1 << 8))
#define VTCR_IRGN_WT           ((2 << 8))
#define VTCR_IRGN_WBnWA        ((3 << 8))
#define VTCR_IRGN_MASK         ((3 << 8))
#define VTCR_ORGN0_WBWC        ((1 << 10))
#define VTCR_ORGN_NC           ((0 << 10))
#define VTCR_ORGN_WBWA         ((1 << 10))
#define VTCR_ORGN_WT           ((2 << 10))
#define VTCR_ORGN_WBnWA        ((3 << 10))
#define VTCR_ORGN_MASK         ((3 << 10))
#define VTCR_SH0_ISH           ((3 << 12))
#define VTCR_TG0_4K            ((0 << 14))
#define VTCR_TG0_64K           ((1 << 14))
#define VTCR_PS_4G             ((0 << 16))
#define VTCR_PS_64G            ((1 << 16))
#define VTCR_PS_1T             ((2 << 16))
#define VTCR_PS_4T             ((3 << 16))
#define VTCR_PS_16T            ((4 << 16))
#define VTCR_PS_256T           ((5 << 16))
#define VTCR_NSA               ((1 << 30))
#define VTCR_NSW               ((1 << 29))

#define VTCR_SH0_SHIFT 12
#define VTCR_SH0_MASK (UL(3) << VTCR_SH0_SHIFT)
#define VTCR_SH0_INNER (UL(3) << VTCR_SH0_SHIFT)


/* VSTCR_EL2 Registers bits */
#define VSTCR_EL2_T0SZ(x)      ((64 - (x)))
#define VSTCR_SL0_2            ((2 << 6))
#define VSTCR_SL0_1            ((1 << 6))
#define VSTCR_SL0_0            ((0 << 6))
#define VSTCR_TG0_4K           ((0 << 14))
#define VSTCR_TG0_64K          ((1 << 14))
#define VSTCR_SW               ((1 << 29))
#define VSTCR_SA               ((1 << 30))
