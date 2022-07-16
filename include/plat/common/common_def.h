/*
 * Copyright (c) 2015-2018, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef COMMON_DEF_H
#define COMMON_DEF_H

#include <platform_def.h>
#include <lib/utils_def.h>

/*
 * Platform binary types for linking
 */
#ifdef AARCH32
#define PLATFORM_LINKER_FORMAT          "elf32-littlearm"
#define PLATFORM_LINKER_ARCH            arm
#else
#define PLATFORM_LINKER_FORMAT          "elf64-littleaarch64"
#define PLATFORM_LINKER_ARCH            aarch64
#endif /* AARCH32 */

/*
 * Generic platform constants
 */
#define FIRMWARE_WELCOME_STR		"Booting Trusted Firmware\n"

#endif /* COMMON_DEF_H */
