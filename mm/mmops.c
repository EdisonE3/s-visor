#include <stdint.h>
#include <string.h>

extern void *__memcpy(void *, const void *, size_t);

void *memcpy(void *dst, const void *src, size_t len) {
    return __memcpy(dst, src, len);
}

void *memset(void *dst, int ch, size_t size) {
	char *d;
	uint64_t i;

	d = (char *)dst;
	for (i = 0; i < size; ++i)
		d[i] = ch;
    return dst;
}

void *memmove(void *dst, const void *src, size_t size) {
	char *d;
	char *s;
	long long i;

	d = (char *)dst;
	s = (char *)src;
	for (i = size; i >= 0; --i)
		d[i] = s[i];
    return dst;
}

void bzero(void *p, size_t size) {
	char *d;
	uint64_t i;

	d = (char *)p;
	for (i = 0; i < size; ++i)
		d[i] = 0;
}

