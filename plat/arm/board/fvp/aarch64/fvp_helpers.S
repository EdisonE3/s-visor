/*
 * Copyright (c) 2013-2017, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <common/asm.h>
#include <arch.h>
#include <asm_macros.S>
#include <platform_def.h>
#include <v2m_def.h>
#include "../fvp_def.h"

	.globl	plat_is_my_cpu_primary
	.globl	plat_arm_calc_core_pos
	.globl 	plat_arm_calc_core_pos_el2

	/* -----------------------------------------------------
	 * unsigned int plat_is_my_cpu_primary (void);
	 *
	 * Find out whether the current cpu is the primary
	 * cpu.
	 * -----------------------------------------------------
	 */
func plat_is_my_cpu_primary
	mrs	x0, mpidr_el1
	mov_imm	x1, MPIDR_AFFINITY_MASK
	and	x0, x0, x1
	cmp	x0, #FVP_PRIMARY_CPU
	cset	w0, eq
	ret
endfunc plat_is_my_cpu_primary

	/* ---------------------------------------------------------------------
	 * unsigned int plat_arm_calc_core_pos(u_register_t mpidr)
	 *
	 * Function to calculate the core position on FVP.
	 *
	 * (ClusterId * FVP_MAX_CPUS_PER_CLUSTER * FVP_MAX_PE_PER_CPU) +
	 * (CPUId * FVP_MAX_PE_PER_CPU) +
	 * ThreadId
	 *
	 * which can be simplified as:
	 *
	 * ((ClusterId * FVP_MAX_CPUS_PER_CLUSTER + CPUId) * FVP_MAX_PE_PER_CPU)
	 * + ThreadId
	 * ---------------------------------------------------------------------
	 */
func plat_arm_calc_core_pos
	/*
	 * Check for MT bit in MPIDR. If not set, shift MPIDR to left to make it
	 * look as if in a multi-threaded implementation.
	 */
	tst	x0, #MPIDR_MT_MASK
	lsl	x3, x0, #MPIDR_AFFINITY_BITS
	csel	x3, x3, x0, eq

	/* Extract individual affinity fields from MPIDR */
	ubfx	x0, x3, #MPIDR_AFF0_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x1, x3, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x2, x3, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS

	/* Compute linear position */
	mov	x4, #FVP_MAX_CPUS_PER_CLUSTER
	madd	x1, x2, x4, x1
	mov	x5, #FVP_MAX_PE_PER_CPU
	madd	x0, x1, x5, x0
	ret
endfunc plat_arm_calc_core_pos

func plat_arm_calc_core_pos_el2

	tst	x0, #MPIDR_MT_MASK
	lsl	x3, x0, #MPIDR_AFFINITY_BITS
	csel	x3, x3, x0, eq

	/* Extract individual affinity fields from MPIDR */
	ubfx	x0, x3, #MPIDR_AFF0_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x1, x3, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x2, x3, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS

	/* Compute linear position */
	mov	x4, #FVP_MAX_CPUS_PER_CLUSTER
	madd	x1, x2, x4, x1
	mov	x5, #FVP_MAX_PE_PER_CPU
	madd	x0, x1, x5, x0
	ret

endfunc plat_arm_calc_core_pos_el2

BEGIN_FUNC(put32)
    str w1,[x0]
    ret
END_FUNC(put32)

BEGIN_FUNC(get32)
    ldr w0,[x0]
    ret
END_FUNC(put32)

BEGIN_FUNC(put64)
    str x1,[x0]
    ret
END_FUNC(put32)

BEGIN_FUNC(get64)
    ldr x0,[x0]
    ret
END_FUNC(put32)
