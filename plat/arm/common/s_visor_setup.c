/*
 * Copyright (c) 2015-2018, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <plat_arm.h>
#include <stdio.h>

/*
 * Placeholder variables for copying the arguments that have been passed to
 * BL31 from BL2.
 */

#if !RESET_TO_BL31
/*
 * Check that BL31_BASE is above ARM_TB_FW_CONFIG_LIMIT. The reserved page
 * is required for SOC_FW_CONFIG/TOS_FW_CONFIG passed from BL2.
 */
CASSERT(BL31_BASE >= ARM_TB_FW_CONFIG_LIMIT, assert_bl31_base_overflows);
#endif

/* Weak definitions may be overridden in specific ARM standard platform */
#pragma weak ti_early_platform_setup2
#pragma weak s_visor_platform_setup
#pragma weak s_visor_plat_get_next_image_ep_info

void s_visor_platform_setup(void)
{
    printf("in s_visor_platform_setup\n");

    return;
}

/*******************************************************************************
 * Perform any BL31 early platform setup common to ARM standard platforms.
 * Here is an opportunity to copy parameters passed by the calling EL (S-EL1
 * in BL2 & EL3 in BL1) before they are lost (potentially). This needs to be
 * done before the MMU is initialized so that the memory layout can be used
 * while creating page tables. BL2 has flushed this information to memory, so
 * we are guaranteed to pick up good data.
 ******************************************************************************/
void __init arm_s_visor_early_platform_setup(void *from_bl31, uintptr_t soc_fw_config,
				uintptr_t hw_config, void *plat_params_from_bl31)
{
	/* Initialize the console to provide early debug support */
	arm_console_boot_init();
	printf("in arm_s_visor_early_platform_setup\n");

#if RESET_TO_BL31
	/* There are no parameters from BL2 if BL31 is a reset vector */
	assert(from_bl31 == NULL);
	assert(plat_params_from_bl31 == NULL);

# ifdef BL32_BASE
	/* Populate entry point information for BL32 */
	SET_PARAM_HEAD(&bl32_image_ep_info,
				PARAM_EP,
				VERSION_1,
				0);
	SET_SECURITY_STATE(bl32_image_ep_info.h.attr, SECURE);
	bl32_image_ep_info.pc = BL32_BASE;
	bl32_image_ep_info.spsr = arm_get_spsr_for_bl32_entry();
# endif /* BL32_BASE */
	/* Populate entry point information for BL33 */
	SET_PARAM_HEAD(&bl33_image_ep_info,
				PARAM_EP,
				VERSION_1,
				0);
	/*
	 * Tell BL31 where the non-trusted software image
	 * is located and the entry state information
	 */
	bl33_image_ep_info.pc = plat_get_ns_image_entrypoint();

	bl33_image_ep_info.spsr = arm_get_spsr_for_bl33_entry();
	SET_SECURITY_STATE(bl33_image_ep_info.h.attr, NON_SECURE);

# if ARM_LINUX_KERNEL_AS_BL33
	/*
	 * According to the file ``Documentation/arm64/booting.txt`` of the
	 * Linux kernel tree, Linux expects the physical address of the device
	 * tree blob (DTB) in x0, while x1-x3 are reserved for future use and
	 * must be 0.
	 */
	bl33_image_ep_info.args.arg0 = (u_register_t)ARM_PRELOADED_DTB_BASE;
	bl33_image_ep_info.args.arg1 = 0U;
	bl33_image_ep_info.args.arg2 = 0U;
	bl33_image_ep_info.args.arg3 = 0U;
# endif

#endif /* RESET_TO_BL31 */
}

void ti_early_platform_setup2(u_register_t arg0, u_register_t arg1,
		u_register_t arg2, u_register_t arg3)
{
	arm_s_visor_early_platform_setup((void *)arg0, arg1, arg2, (void *)arg3);
}
