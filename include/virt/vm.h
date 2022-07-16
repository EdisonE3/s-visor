#pragma once
#include <common/list.h>
#include <common/def.h>
#include <virt/vcpu.h>
#include <stdio.h>

#define MAX_VCPU_NUM 8

#define GPA_START 0x40000000
#define GPA_LENGTH (512 << 20)
#define KERNEL_IPN_START 0x40080 
#define IMAGE_SIZE 0x433808
#define PAGE_UPPER(x) ( ( x + PAGE_SIZE - 1 ) >> 12 )

#define Op0_shift	19
#define Op0_mask	0x3
#define Op1_shift	16
#define Op1_mask	0x7
#define CRn_shift	12
#define CRn_mask	0xf
#define CRm_shift	8
#define CRm_mask	0xf
#define Op2_shift	5
#define Op2_mask	0x7

#define sys_reg(op0, op1, crn, crm, op2) \
	(((op0) << Op0_shift) | ((op1) << Op1_shift) | \
	 ((crn) << CRn_shift) | ((crm) << CRm_shift) | \
	 ((op2) << Op2_shift))

enum vm_state {
    VS_CREATE = 0,
    VS_INIT,
    VS_READY,
    VS_RUNNING,
    VS_DESTROY,
};

enum vm_type {
    VT_KVM,
};

struct s_visor_vm {
    int vm_id;                                       // VM ID
    char *vm_name;                                   // VM name, used for debugging

    struct list_head vm_list_node;                   // link all vm in the same list

    struct s_visor_vcpu *vcpus[MAX_VCPU_NUM];       // all VCPUs
    unsigned int nr_vcpu;

    struct thread_vector_table *thread_vector_table; // Trusted OS callback table
    struct s_visor_vm_ops *vm_ops;                   // VM specific operations
    struct s2mmu *s2mmu;                             // stage 2 mmu struct
    /* s2mmu used by KVM */
    unsigned long saved_s2mmu;

    int vm_state;                                   
    int vm_type;  
   
	struct list_head cache_list;

    /* s1mmu of QEMU */
    uint64_t qemu_s1ptp;
    /* Currently, we support 3 vqs, 1 for virtio-blk, 2 for virtio-net */
    int init_qid;

    struct virtio_queue *vqs[3];
    struct vring *vrings[3];
    struct vring *shadow_vrings[3];
	
    uint16_t last_avail_ids[3];
    uint16_t last_used_ids[3];

    int migrated;
};

struct sec_mem_pool {
    uint64_t start_pfn;
    uint64_t cur_top_pfn;
    uint64_t end_pfn; // one-past-the-last pfn
    uint64_t *bitmap;
};

extern struct sec_mem_pool mem_pools[3];

struct vm_cache {
    uint64_t base_pfn;
    struct list_head node_for_list;
};

void init_bitmap(int pool_id);
void free_bitmap(int pool_id);

/* Use a bitmap to record if a cache is used by a VM */
static inline void set_cache_used(int pool_id, uint64_t base_pfn) {
    uint64_t cache_idx = (base_pfn - mem_pools[pool_id].start_pfn) >> 11; // 8M cache for a VM
    uint16_t row = cache_idx / 64; 
    uint16_t col = cache_idx % 64;
    printf("%s pool_id %d, base_pfn 0x%llx, row %d, col %d\n", __func__, pool_id, base_pfn, row, col);
    mem_pools[pool_id].bitmap[row] |= (1 << col);
}

static inline void set_cache_free(int pool_id, uint64_t base_pfn) {
    uint16_t cache_idx = (base_pfn - mem_pools[pool_id].start_pfn) >> 11;
    uint16_t row = cache_idx / 64; 
    uint16_t col = cache_idx % 64;
    printf("%s pool_id %d, base_pfn 0x%llx, row %d, col %d\n", __func__, pool_id, base_pfn, row, col);
    mem_pools[pool_id].bitmap[row] &= ~(1 << col);
}

static inline int check_cache_state(int pool_id, uint64_t base_pfn) {
    uint16_t cache_idx = (base_pfn - mem_pools[pool_id].start_pfn) >> 11;
    uint16_t row = cache_idx / 64; 
    uint16_t col = cache_idx % 64;
    return !!(mem_pools[pool_id].bitmap[row] & (1 << col));
}

/* Add the cache to the list of vm */
void add_cache_to_vm(struct s_visor_vm *vm, struct vm_cache *cache);

/* Remove the cache from the list of vm */
void rm_cache_from_vm(struct s_visor_vm *vm, struct vm_cache *cache);

/* Validate src pfn before migration */
int pfn_belongs_to_vm(struct s_visor_vm *vm, uint64_t pfn);

enum pfn_type {
    PFN_IN_USE, 
    PFN_SEC_FREE,
    PFN_NON_SEC,
    PFN_INVALID,
};

/* Return -1 if invalid, 0 if in use, 1 if free */
int validate_pfn(int pool_id, uint64_t pfn);
/* Return -1 if invalid, 0 if in use, 1 if free */
int validate_top_pfn(int pool_id, uint64_t pfn);
void update_top_pfn(int, uint64_t);
uint64_t get_top_pfn_of_vm(int pool_id, struct s_visor_vm *vm);
uint64_t get_top_pfn_of_all(int pool_id);
void rm_all_caches_from_vm(int pool_id, struct s_visor_vm *kvm_vm);

void init_vms(void);
struct s_visor_vm *get_vm_by_id(int vm_id);
void cold_boot_vms(void);
uint64_t __get_core_pos();

