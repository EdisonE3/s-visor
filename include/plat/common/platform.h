/*
 * Copyright (c) 2013-2018, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>

int plat_crash_console_putc(int c);
void plat_panic_handler(void) __dead2;

void readCurEL(char *s);

/*******************************************************************************
 * Mandatory BL31 functions
 ******************************************************************************/
void ti_early_platform_setup2(u_register_t arg0, u_register_t arg1,
		u_register_t arg2, u_register_t arg3);
struct entry_point_info *s_visor_plat_get_next_image_ep_info(uint32_t type);

void s_visor_platform_setup(void);

#endif /* PLATFORM_H */
