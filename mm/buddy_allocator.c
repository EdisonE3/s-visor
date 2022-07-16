#include <mm/buddy_allocator.h>
#include <mm/tlsf.h>
#include <mm/mm.h>
#include <mm/mmu_def.h>
#include <common/lock.h>
#include <virt/sel2.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define LEAF_SIZE       PAGE_SIZE
#define MEM_BASE        0x06400000UL
#define MEM_END         0x08000000UL

struct lock secure_alloc_lock;
tlsf_t secure_tlsf = NULL;

void bd_init() {
    memset((void *)MEM_BASE, 0, MEM_END - MEM_BASE);
    lock_init(&secure_alloc_lock);
    secure_tlsf = tlsf_create_with_pool((void *)MEM_BASE, MEM_END - MEM_BASE);
}

void *bd_alloc(uint64_t nbytes, uint64_t alignment) {
    void *align_ptr = NULL;
    lock(&secure_alloc_lock);
    align_ptr = tlsf_memalign(secure_tlsf, (1 << alignment), nbytes);
    if (!align_ptr || ((uint64_t)align_ptr & ((1 << alignment) - 1))) {
        printf("[Buddy Alloc] OOM\n");
        hyp_panic();
    }
    unlock(&secure_alloc_lock);
    return align_ptr;
}

void bd_free(void* ptr) {
    lock(&secure_alloc_lock);
    tlsf_free(secure_tlsf, ptr);
    unlock(&secure_alloc_lock);
}
