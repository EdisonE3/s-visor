#pragma once
#include <stdint.h>

struct s_visor_handler_table {
	uint32_t std_smc_entry;
	uint32_t fast_smc_entry;
	uint32_t fiq_entry;
};
extern struct s_visor_handler_table s_visor_handler_table;
