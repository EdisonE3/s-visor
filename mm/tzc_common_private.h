/*
 * Copyright (c) 2016-2018, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TZC_COMMON_PRIVATE_H
#define TZC_COMMON_PRIVATE_H

//#include <arch.h>
//#include <arch_helpers.h>
#include <mm/tzc_common.h>

static inline void mmio_write_32(uintptr_t addr, uint32_t value) {
	*(volatile uint32_t*)addr = value;
}

static inline uint32_t mmio_read_32(uintptr_t addr) {
	return *(volatile uint32_t*)addr;
}

#define DEFINE_TZC_COMMON_WRITE_ACTION(fn_name, macro_name)		\
	static inline void _tzc##fn_name##_write_action(		\
					uintptr_t base,			\
					unsigned int action)		\
	{								\
		mmio_write_32(base + TZC_##macro_name##_ACTION_OFF,	\
			action);					\
	}

#define DEFINE_TZC_COMMON_WRITE_REGION_BASE(fn_name, macro_name)	\
	static inline void _tzc##fn_name##_write_region_base(		\
					uintptr_t base,			\
					unsigned int region_no,		\
					unsigned long long region_base)	\
	{								\
		mmio_write_32(base +					\
			TZC_REGION_OFFSET(				\
				TZC_##macro_name##_REGION_SIZE,		\
				region_no) +				\
			TZC_##macro_name##_REGION_BASE_LOW_0_OFFSET,	\
			(uint32_t)region_base);				\
		mmio_write_32(base +					\
			TZC_REGION_OFFSET(				\
				TZC_##macro_name##_REGION_SIZE,		\
				region_no) +				\
			TZC_##macro_name##_REGION_BASE_HIGH_0_OFFSET,	\
			(uint32_t)(region_base >> 32));			\
	}

#define DEFINE_TZC_COMMON_WRITE_REGION_TOP(fn_name, macro_name)		\
	static inline void _tzc##fn_name##_write_region_top(		\
					uintptr_t base,			\
					unsigned int region_no,		\
					unsigned long long region_top)	\
	{								\
		mmio_write_32(base +					\
			TZC_REGION_OFFSET				\
				(TZC_##macro_name##_REGION_SIZE,	\
				region_no) +				\
			TZC_##macro_name##_REGION_TOP_LOW_0_OFFSET,	\
			(uint32_t)region_top);				\
		mmio_write_32(base +					\
			TZC_REGION_OFFSET(				\
				TZC_##macro_name##_REGION_SIZE,		\
				region_no) +				\
			TZC_##macro_name##_REGION_TOP_HIGH_0_OFFSET,	\
			(uint32_t)(region_top >> 32));			\
	}

#define DEFINE_TZC_COMMON_WRITE_REGION_ATTRIBUTES(fn_name, macro_name)	\
	static inline void _tzc##fn_name##_write_region_attributes(	\
						uintptr_t base,		\
						unsigned int region_no,	\
						unsigned int attr)	\
	{								\
		mmio_write_32(base +					\
			TZC_REGION_OFFSET(				\
				TZC_##macro_name##_REGION_SIZE,		\
				region_no) +				\
			TZC_##macro_name##_REGION_ATTR_0_OFFSET,	\
			attr);						\
	}

#define DEFINE_TZC_COMMON_WRITE_REGION_ID_ACCESS(fn_name, macro_name)	\
	static inline void _tzc##fn_name##_write_region_id_access(	\
						uintptr_t base,		\
						unsigned int region_no,	\
						unsigned int val)	\
	{								\
		mmio_write_32(base +					\
			TZC_REGION_OFFSET(				\
				TZC_##macro_name##_REGION_SIZE,		\
				region_no) +				\
			TZC_##macro_name##_REGION_ID_ACCESS_0_OFFSET,	\
			val);						\
	}

/*
 * It is used to program a region from 1 to 8 in the TrustZone controller.
 * NOTE:
 * Region 0 is special; it is preferable to use
 * ##fn_name##_configure_region0 for this region (see comment for
 * that function).
 */
#define DEFINE_TZC_COMMON_CONFIGURE_REGION(fn_name)			\
	static void _tzc##fn_name##_configure_region(uintptr_t base,	\
				unsigned int filters,			\
				unsigned int region_no,			\
				unsigned long long region_base,		\
				unsigned long long region_top,		\
				unsigned int sec_attr,			\
				unsigned int nsaid_permissions)		\
	{								\
		VERBOSE("TrustZone : Configuring region "		\
			"(TZC Interface Base: 0x%lx, region_no = %u)"	\
			"...\n", base, region_no);			\
		VERBOSE("TrustZone : ... base = %llx, top = %llx,"	\
			"\n", region_base, region_top);			\
		VERBOSE("TrustZone : ... sec_attr = 0x%x,"		\
			" ns_devs = 0x%x)\n",				\
			sec_attr, nsaid_permissions);			\
									\
		/***************************************************/	\
		/* Inputs look ok, start programming registers.    */	\
		/* All the address registers are 32 bits wide and  */	\
		/* have a LOW and HIGH				   */	\
		/* component used to construct an address up to a  */	\
		/* 64bit.					   */	\
		/***************************************************/	\
		_tzc##fn_name##_write_region_base(base,			\
					region_no, region_base);	\
		_tzc##fn_name##_write_region_top(base,			\
					region_no, region_top);		\
									\
		/* Enable filter to the region and set secure attributes */\
		_tzc##fn_name##_write_region_attributes(base,		\
				region_no,				\
				(sec_attr << TZC_REGION_ATTR_SEC_SHIFT) |\
				(filters << TZC_REGION_ATTR_F_EN_SHIFT));\
									\
		/***************************************************/	\
		/* Specify which non-secure devices have permission*/	\
		/* to access this region.			   */	\
		/***************************************************/	\
		_tzc##fn_name##_write_region_id_access(base,		\
						region_no,		\
						nsaid_permissions);	\
	}

static inline unsigned int _tzc_read_peripheral_id(uintptr_t base) {
	unsigned int id;

	id = mmio_read_32(base + PID0_OFF);
	/* Masks DESC part in PID1 */
	id |= ((mmio_read_32(base + PID1_OFF) & 0xFU) << 8U);

	return id;
}

#endif /* TZC_COMMON_PRIVATE_H */
