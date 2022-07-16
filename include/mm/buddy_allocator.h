#pragma once
#include <stdint.h>

void bd_init(void);
void *bd_alloc(uint64_t nbytes, uint64_t alignment);
void bd_free(void* ptr);

void shadow_bd_init(void);
void *shadow_bd_alloc(uint64_t nbytes, uint64_t alignment);
void shadow_bd_free(void *ptr);
