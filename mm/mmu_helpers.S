#include <mm/mmu_def.h>
#include <common/asm.h>

/* SCTLR_EL2 System Control Register aarch64 */

#define SCTLR_EL2_EE                BIT(25)     /* Endianness of data accesses at EL2, and stage 1 translation table walks in the EL2&0 translation regime */
#define SCTLR_EL2_WXN               BIT(19)     /* Write permission implies XN (Execute-never) */
#define SCTLR_EL2_I                 BIT(12)     /* Instruction access Cacheability control, for accesses at EL2 */
#define SCTLR_EL2_SA                BIT(3)      /* SP Alignment check */
#define SCTLR_EL2_C                 BIT(2)      /* Cacheability control for data accesses */
#define SCTLR_EL2_A                 BIT(1)      /* Alignment check enable */
#define SCTLR_EL2_M                 BIT(0)      /* MMU enable for EL2 stage 1 address translation */

#define TCR_T0SZ(x)       ((64 - (x)))
#define TCR_T1SZ(x)       ((64 - (x)) << 16)
#define TCR_TxSZ(x)       (TCR_T0SZ(x) | TCR_T1SZ(x))

#define TCR_IRGN0_WBWC    (1 << 8)
#define TCR_IRGN_NC       ((0 << 8) | (0 << 24))
#define TCR_IRGN_WBWA     ((1 << 8) | (1 << 24))
#define TCR_IRGN_WT       ((2 << 8) | (2 << 24))
#define TCR_IRGN_WBnWA    ((3 << 8) | (3 << 24))
#define TCR_IRGN_MASK     ((3 << 8) | (3 << 24))

#define TCR_ORGN0_WBWC    (1 << 10)
#define TCR_ORGN_NC       ((0 << 10) | (0 << 26))
#define TCR_ORGN_WBWA     ((1 << 10) | (1 << 26))
#define TCR_ORGN_WT       ((2 << 10) | (2 << 26))
#define TCR_ORGN_WBnWA    ((3 << 10) | (3 << 26))
#define TCR_ORGN_MASK     ((3 << 10) | (3 << 26))

#define TCR_SH0_ISH       (3 << 12)

#define TCR_TG0_4K        (0 << 14)
#define TCR_TG0_64K       (1 << 14)
#define TCR_TG1_4K        (2 << 30)
#define TCR_TG1_64K       (3 << 30)

#define TCR_PS_4G         (0 << 16)
#define TCR_PS_64G        (1 << 16)
#define TCR_PS_1T         (2 << 16)
#define TCR_PS_4T         (3 << 16)
#define TCR_PS_16T        (4 << 16)
#define TCR_PS_256T       (5 << 16)

/* bits are reserved as 1 */
#define TCR_EL2_RES1      ((1 << 23) | (1 << 31))
#define TCR_ASID16        (1 << 36)

#define UL(x) x##UL

#define TCR_SH0_SHIFT 12
#define TCR_SH0_MASK (UL(3) << TCR_SH0_SHIFT)
#define TCR_SH0_INNER (UL(3) << TCR_SH0_SHIFT)
#define TCR_SH1_SHIFT 28
#define TCR_SH1_MASK (UL(3) << TCR_SH1_SHIFT)
#define TCR_SH1_INNER (UL(3) << TCR_SH1_SHIFT)

#define TCR_SHARED (TCR_SH0_INNER | TCR_SH1_INNER)

#define TCR_TBI0 (UL(1) << 37)
#define TCR_A1   (UL(1) << 22)


#define ID_AA64PFR0_EL2_GIC     (0b1111 << 24)

#define MT_DEVICE_nGnRnE  0
#define MT_DEVICE_nGnRE   1
#define MT_DEVICE_GRE     2
#define MT_NORMAL_NC      3
#define MT_NORMAL         4
#define MAIR(_attr, _mt)  ((_attr) << ((_mt) * 8))


.extern _boot_pt_l0_0
.extern _boot_pt_l0_1


LOCAL_FUNC_BEGIN(flush_dcache)
    dcache  cisw
    ret
LOCAL_FUNC_END(flush_dcache)

LOCAL_FUNC_BEGIN(invalidate_dcache)
    dcache  isw
    ret
LOCAL_FUNC_END(invalidate_dcache)

LOCAL_FUNC_BEGIN(invalidate_icache)
    ic      iallu
    dsb     nsh
    isb
    ret
LOCAL_FUNC_END(invalidate_icache)

BEGIN_FUNC(flush_dcache_and_tlb)
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    tlbi    alle2
    dsb     sy
    isb
    
    ic      ialluis

    bl      flush_dcache

    ldp     x29, x30, [sp], #16
    ret
END_FUNC(flush_dcache_and_tlb)

.macro enable_mmu sctlr tmp
	mrs     \tmp, \sctlr
    /* Enable MMU */
	orr     \tmp, \tmp, #SCTLR_EL2_M
    /* Disable alignment checking */
	bic     \tmp, \tmp, #SCTLR_EL2_A
	bic     \tmp, \tmp, #SCTLR_EL2_SA
	/* Data accesses Cacheable */
        orr     \tmp, \tmp, #SCTLR_EL2_C
    /* Instruction access Cacheable */
	orr     \tmp, \tmp, #SCTLR_EL2_I
	msr     \sctlr, \tmp
	isb
.endm

.macro disable_mmu sctlr tmp
	mrs     \tmp, \sctlr
    /* Disable MMU */
	bic     \tmp, \tmp, #SCTLR_EL2_M
    /* Disable alignment checking */
	bic     \tmp, \tmp, #SCTLR_EL2_A
	bic     \tmp, \tmp, #SCTLR_EL2_SA
	bic     \tmp, \tmp, #SCTLR_EL2_C
    /* Disable Instruction Cache */
	bic     \tmp, \tmp, #SCTLR_EL2_I
	msr     \sctlr, \tmp
	isb
.endm


BEGIN_FUNC(activate_mmu)
    /* We call nested functions, follow the ABI. */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    bl      flush_dcache

    /* Ensure I-cache, D-cache and mmu are disabled for EL1/Stage1 */
    disable_mmu sctlr_el2 , x8

    /*
     * Invalidate the local I-cache so that any instructions fetched
     * speculatively are discarded.
     */
    bl      invalidate_icache

    /*
     *   DEVICE_nGnRnE      000     00000000
     *   DEVICE_nGnRE       001     00000100
     *   DEVICE_GRE         010     00001100
     *   NORMAL_NC          011     01000100
     *   NORMAL             100     11111111
     */
    ldr     x5, =MAIR(0x00, MT_DEVICE_nGnRnE) |\
                 MAIR(0x04, MT_DEVICE_nGnRE) |\
                 MAIR(0x0c, MT_DEVICE_GRE) |\
                 MAIR(0x44, MT_NORMAL_NC) |\
                 MAIR(0xff, MT_NORMAL)
    msr     mair_el2, x5

    ldr     x10, =TCR_TxSZ(48) | TCR_IRGN_WBWA | TCR_ORGN_WBWA | TCR_TG0_4K | TCR_TG1_4K | TCR_ASID16 | TCR_SHARED | TCR_PS_64G

    mrs     x9, ID_AA64MMFR0_EL1
    bfi     x10, x9, #32, #3
    msr     tcr_el2, x10

    /* Setup page tables */
    adrp    x8, _boot_pt_l0_0
    msr     ttbr0_el2, x8
//    adrp    x8, _boot_pt_l1_1
//    msr     ttbr1_el2, x8
    isb

    /* invalidate all TLB entries for EL2 */
    tlbi    vmalle1is
    dsb     ish
    isb

    enable_mmu sctlr_el2 , x8

    ldp     x29, x30, [sp], #16
    ret
END_FUNC(activate_mmu)
