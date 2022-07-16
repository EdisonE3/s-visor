#include <common/def.h>

#include <virt/vm.h>
#include <stdio.h>
#include <mm/buddy_allocator.h>

struct sec_mem_pool mem_pools[3];
extern struct list_head s_visor_vm_list;

void init_bitmap(int pool_id) {
    uint64_t size = ((1UL << 30) / (8 << 20) / 8);
    mem_pools[pool_id].bitmap = (uint64_t *)bd_alloc(size, 0);
}

void free_bitmap(int pool_id) {
    uint64_t addr = (uint64_t)mem_pools[pool_id].bitmap;
    bd_free((void *)addr);
}

void add_cache_to_vm(struct s_visor_vm *vm, struct vm_cache *cache) {
    list_push(&vm->cache_list, &cache->node_for_list);
}

void rm_cache_from_vm(struct s_visor_vm *vm, struct vm_cache *cache) {
    list_remove(&cache->node_for_list);
}

int pfn_belongs_to_vm(struct s_visor_vm *vm, uint64_t pfn) {
    struct vm_cache *cache = NULL;
    uint64_t base_pfn = pfn & ~(0x7ff); // 8M-aligned
    for_each_in_list(cache, struct vm_cache, 
            node_for_list, &vm->cache_list) {
        if (base_pfn == cache->base_pfn)
            return 1;
    }
    return 0;
}

void rm_all_caches_from_vm(int pool_id, struct s_visor_vm *vm) {
    struct vm_cache *cache = NULL;

    while (!list_empty(&vm->cache_list)) {
        cache = container_of(list_pop(&vm->cache_list), struct vm_cache, node_for_list);

        set_cache_free(pool_id, cache->base_pfn);
        bd_free(cache);
    }
    return;
}

uint64_t get_top_pfn_of_vm(int pool_id, struct s_visor_vm *vm) {
    struct vm_cache *cache = NULL;
    uint64_t top_pfn = 0;
    for_each_in_list(cache, struct vm_cache, 
            node_for_list, &vm->cache_list) {
        if (top_pfn < cache->base_pfn)
            top_pfn = cache->base_pfn;
    }
    return top_pfn + (1 << 23 >> 12);
}

uint64_t get_top_pfn_of_all(int pool_id) {
    struct s_visor_vm* vm = NULL;
    uint64_t top_pfn = 0;
    for_each_in_list(vm, struct s_visor_vm, 
            vm_list_node ,&s_visor_vm_list) {
        unsigned long top_pfn_vm = get_top_pfn_of_vm(pool_id, vm);
        if (top_pfn < top_pfn_vm) {
            top_pfn = top_pfn_vm;
        }
    }
    return top_pfn;
}

void update_top_pfn(int pool_id, uint64_t top_pfn) {
    if (top_pfn >= mem_pools[pool_id].start_pfn)
        mem_pools[pool_id].cur_top_pfn = top_pfn;
    else {
        mem_pools[pool_id].cur_top_pfn = mem_pools[pool_id].start_pfn;
    }
    
    printf("mem pool top is 0x%llx\n", mem_pools[pool_id].cur_top_pfn);
}

int validate_pfn(int pool_id, uint64_t pfn) {
    uint64_t base_pfn = pfn & ~(0x7ff); // 8M-aligned
    if (base_pfn < mem_pools[pool_id].start_pfn ||
            mem_pools[pool_id].end_pfn <= base_pfn) {
        return PFN_INVALID;
    }

    if (base_pfn < mem_pools[pool_id].cur_top_pfn) {
        return check_cache_state(pool_id, base_pfn) ? 
            PFN_IN_USE : PFN_SEC_FREE;
    } else {
        return PFN_NON_SEC;
    }
}

int validate_top_pfn(int pool_id, uint64_t top_pfn) {
    printf("mem pool top is 0x%llx, applied top is 0x%llx\n", 
            mem_pools[pool_id].cur_top_pfn, top_pfn);
    uint64_t top_base_pfn = top_pfn & ~(0x7ff); // 8M-aligned
    if (top_base_pfn < mem_pools[pool_id].cur_top_pfn) {
        return 0;
    } else {
        return 1;
    }
}
