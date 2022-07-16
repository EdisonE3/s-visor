#include <virt/stage2_mmu_def.h>
#include <virt/asm-offsets.h>
#include <common/asm.h>


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



.macro enable_hcr hcr tmp
    mov     \tmp, #0
    /* Enable MMU */
    orr     \tmp, \tmp, #HCR_SEL2_VM
    orr     \tmp, \tmp, #HCR_SEL2_RW
    orr     \tmp, \tmp, #HCR_SEL2_FMO
    orr     \tmp, \tmp, #HCR_SEL2_TSC
//    orr     \tmp, \tmp, #HCR_SEL2_HCD
    msr     \hcr, \tmp
    isb
.endm

.extern _boot_stage2_pt_l0

BEGIN_FUNC(enable_hyp_mode)
    enable_hcr hcr_el2, x10
END_FUNC(enable_hyp_mode)

BEGIN_FUNC(activate_stage2_mmu)
    /* We call nested functions, follow the ABI. */
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    bl      flush_dcache

    /*
     * Invalidate the local I-cache so that any instructions fetched
     * speculatively are discarded.
     */
    bl      invalidate_icache

    ldr     x10, =VSTCR_SL0_1 | VSTCR_TG0_4K | VSTCR_EL2_T0SZ(40)
    msr     vstcr_el2, x10

    ldr     x10, =VTCR_SL0_L1 | VTCR_NSA |  VTCR_TG0_4K |  VTCR_PS_1T | VTCR_SH0_ISH |  VTCR_EL2_T0SZ(40)
    msr     vtcr_el2, x10

    tlbi    alle2
    dsb     ish
    isb

    ldp     x29, x30, [sp], #16
    ret
END_FUNC(activate_stage2_mmu)
