#pragma once

#include <stdint.h>

struct lock_impl {
	volatile uint32_t owner;
	volatile uint32_t next;
};
