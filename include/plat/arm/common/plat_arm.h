/*
 * Copyright (c) 2015-2018, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef PLAT_ARM_H
#define PLAT_ARM_H

#include <stdint.h>

#include <lib/cassert.h>
#include <lib/spinlock.h>
#include <lib/utils_def.h>

/*******************************************************************************
 * Forward declarations
 ******************************************************************************/
struct meminfo;
struct image_info;
struct bl_params;

typedef struct arm_tzc_regions_info {
	unsigned long long base;
	unsigned long long end;
	unsigned int sec_attr;
	unsigned int nsaid_permissions;
} arm_tzc_regions_info_t;

/*******************************************************************************
 * Default mapping definition of the TrustZone Controller for ARM standard
 * platforms.
 * Configure:
 *   - Region 0 with no access;
 *   - Region 1 with secure access only;
 *   - the remaining DRAM regions access from the given Non-Secure masters.
 ******************************************************************************/

#define ARM_CASSERT_MMAP						  \
	CASSERT((ARRAY_SIZE(plat_arm_mmap) - 1) <= PLAT_ARM_MMAP_ENTRIES, \
		assert_plat_arm_mmap_mismatch);				  \
	CASSERT((PLAT_ARM_MMAP_ENTRIES + ARM_BL_REGIONS)		  \
		<= MAX_MMAP_REGIONS,					  \
		assert_max_mmap_regions);

void arm_setup_romlib(void);

/* ARM State switch error codes */
#define STATE_SW_E_PARAM		(-2)
#define STATE_SW_E_DENIED		(-3)

/* IO storage utility functions */
void arm_io_setup(void);

/* Console utility functions */
void arm_console_boot_init(void);
/* Systimer utility function */
void arm_configure_sys_timer(void);

#endif /* PLAT_ARM_H */
