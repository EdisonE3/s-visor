#pragma once
#include <stdint.h>

#define BUG_ON(expr, str) \
    do { \
        if ((expr)) { \
            printf("BUG: %s:%d %s\n", __func__, __LINE__, #expr); \
            for(;;) { \
            } \
        } \
    } while (0)

#define BUG(str) \
    do { \
        printf("BUG: %s:%d %s\n", __func__, __LINE__, str); \
        for(;;) { \
        } \
    } while (0)

#define ROUND_UP(x, n)		(((x) + (n) - 1) & ~((n) - 1))
#define ROUND_DOWN(x, n)	((x) & ~((n) - 1))

#define container_of(ptr, type, field) \
	((type *)((void *)(ptr) - (uint64_t)(&(((type *)(0))->field))))
