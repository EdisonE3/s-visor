#pragma once

#include <stdint.h>

struct lock {
	volatile uint64_t slock;
};

int lock_init(struct lock *lock);
void lock(struct lock *lock);
/* returns 0 on success, -1 otherwise */
int try_lock(struct lock *lock);
void unlock(struct lock *lock);
int is_locked(struct lock *lock);
