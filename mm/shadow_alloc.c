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
#define MEM_BASE        0x900000000UL
#define MEM_END         0x940000000UL

struct lock shadow_alloc_lock;
tlsf_t shadow_tlsf = NULL;

void shadow_bd_init() {
    lock_init(&shadow_alloc_lock);
    shadow_tlsf = tlsf_create_with_pool((void *)MEM_BASE, MEM_END - MEM_BASE);
}

void *shadow_bd_alloc(uint64_t nbytes, uint64_t alignment) {
    void *align_ptr = NULL;
    lock(&shadow_alloc_lock);
    align_ptr = tlsf_memalign(shadow_tlsf, (1 << alignment), nbytes);
    if (!align_ptr || ((uint64_t)align_ptr & ((1 << alignment) - 1))) {
        printf("[Shadow Buddy Alloc] OOM\n");
        hyp_panic();
    }
    unlock(&shadow_alloc_lock);
    return align_ptr;
}

void shadow_bd_free(void* ptr) {
    lock(&shadow_alloc_lock);
    tlsf_free(shadow_tlsf, ptr);
    unlock(&shadow_alloc_lock);
}
