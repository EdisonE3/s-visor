#include <common/errno.h>
#include <common/list.h>
#include <common/def.h>
#include <common/lock.h>
#include <virt/vm.h>
#include <virt/vcpu.h>
#include <virt/stage2_mmu.h>
#include <virt/stage2_mmu_def.h>
#include <virt/vmexit_def.h>
#include <virt/virtio_ring.h>
#include <virt/kvm_relay.h>
#include <virt/vm_handler.h>
#include <virt/sel2.h>
#include <mm/buddy_allocator.h>
#include <mm/stage1_mmu.h>
#include <mm/mm.h>
#include <mm/tzc400.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <arch_helpers.h>

extern struct lock tzc_lock;
extern uint64_t *shared_register_pages;

extern struct list_head s_visor_vm_list;
extern struct s_visor_state global_s_visor_states[PHYSICAL_CORE_NUM];
uint64_t __get_core_pos(void);
extern unsigned long cache_number_start;
extern unsigned long cache_number_end;
void flush_dcache_and_tlb(void);

void *get_gp_reg_region(unsigned int core_id)
{
    uint64_t *ptr = shared_register_pages + core_id * S_VISOR_MAX_SIZE_PER_CORE;
    return (void *)ptr;
}

kvm_smc_req_t *get_smc_req_region(unsigned int core_id)
{
    uint64_t *ptr = shared_register_pages + core_id * S_VISOR_MAX_SIZE_PER_CORE;
    /* First 32 entries are for guest gp_regs */
    return (kvm_smc_req_t *)(ptr + 32);
}
/*
 * Create an empty vm struct for holding KVM controlling information
 */
static int init_empty_vm(struct s_visor_vm *vm, int vm_id, char *vm_name, int vcpu_num)
{
    int i = 0;
    if (vm == NULL)
    {
        return -EINVAL;
    }
    memset(vm, 0, sizeof(struct s_visor_vm));

    vm->vm_id = vm_id;
    vm->vm_name = vm_name;

    /* create VCPUs for this VM */
    for (i = 0; i < vcpu_num; i++)
    {
        struct s_visor_vcpu *vcpu = (struct s_visor_vcpu *)bd_alloc(sizeof(*vcpu), 0);
        memset(vcpu, 0, sizeof(struct s_visor_vcpu));
        vcpu->vm = vm;
        vcpu->vcpu_id = i;

        vcpu->vcpu_state = VCPU_READY;

        vcpu->first_entry = true;

        vm->vcpus[i] = vcpu;
    }

    vm->nr_vcpu = vcpu_num;

    list_init(&vm->cache_list);

    vm->init_qid = 0;
    for (i = 0; i < 3; i++)
    {
        struct virtio_queue *vq =
            (struct virtio_queue *)bd_alloc(sizeof(struct virtio_queue), 0);
        memset(vq, 0, sizeof(struct virtio_queue));
        vm->vqs[i] = vq;

        struct vring *vring = (struct vring *)bd_alloc(sizeof(struct vring), 0);
        memset(vring, 0, sizeof(struct vring));
        vm->vrings[i] = vring;

        struct vring *s_vring = (struct vring *)bd_alloc(sizeof(struct vring), 0);
        memset(s_vring, 0, sizeof(struct vring));
        vm->shadow_vrings[i] = s_vring;

        vm->last_avail_ids[i] = 0;
        vm->last_used_ids[i] = 0;
    }

    vm->vm_state = VS_READY;
    vm->vm_type = VT_KVM;

    vm->migrated = 0;

    return 0;
}

static int s_visor_vm_enqueue(struct s_visor_vm *vm)
{
    if (vm == NULL)
    {
        return -EINVAL;
    }

    list_push(&s_visor_vm_list, &(vm->vm_list_node));
    return 0;
}

static int s_visor_vm_dequeue(struct s_visor_vm *vm)
{
    if (vm == NULL)
    {
        return -EINVAL;
    }

    list_remove(&(vm->vm_list_node));
    return 0;
}

/*
 * Create an empty s2mmu struct
 */
static void destroy_stage2_mmu(struct s2mmu *s2mmu)
{
    s2mmu_unmap_range(s2mmu, GPA_START, GPA_LENGTH);
    bd_free(s2mmu->pgtbl);
    bd_free(s2mmu);
}

static void destroy_kvm_vm(struct s_visor_vm *vm, int vcpu_num)
{
    int i = 0;
    if (vm == NULL)
    {
        return;
    }

    for (i = 0; i < vcpu_num; i++)
    {
        bd_free(vm->vcpus[i]);
    }
    for (i = 0; i < 3; i++)
    {
        bd_free(vm->vqs[i]);
        bd_free(vm->vrings[i]);
        bd_free(vm->shadow_vrings[i]);
    }
}


static int only_init_empty_vm(struct s_visor_vm *vm, int vm_id, char *vm_name, int vcpu_num)
{
    int i = 0;
    if (vm == NULL)
    {
        return -EINVAL;
    }
    memset(vm, 0, sizeof(struct s_visor_vm));

    vm->vm_id = vm_id;
    vm->vm_name = vm_name;

    vm->nr_vcpu = vcpu_num;

    list_init(&vm->cache_list);

    vm->init_qid = 0;
    for (i = 0; i < 3; i++)
    {
        struct virtio_queue *vq =
            (struct virtio_queue *)bd_alloc(sizeof(struct virtio_queue), 0);
        memset(vq, 0, sizeof(struct virtio_queue));
        vm->vqs[i] = vq;

        struct vring *vring = (struct vring *)bd_alloc(sizeof(struct vring), 0);
        memset(vring, 0, sizeof(struct vring));
        vm->vrings[i] = vring;

        struct vring *s_vring = (struct vring *)bd_alloc(sizeof(struct vring), 0);
        memset(s_vring, 0, sizeof(struct vring));
        vm->shadow_vrings[i] = s_vring;

        vm->last_avail_ids[i] = 0;
        vm->last_used_ids[i] = 0;
    }

    vm->vm_state = VS_CREATE;
    vm->vm_type = VT_KVM;

    vm->migrated = 0;

    printf("vm: %d state: %d\n", vm->vm_id, vm->vm_state);
    return 0;
}

static int only_init_empty_vcpu(struct s_visor_vm *vm){
    unsigned int nr_vcpu = vm->nr_vcpu;
    unsigned int i;
    for (i = 0; i < nr_vcpu; i++)
    {
        struct s_visor_vcpu *vcpu = (struct s_visor_vcpu *)bd_alloc(sizeof(*vcpu), 0);
        memset(vcpu, 0, sizeof(struct s_visor_vcpu));
        vcpu->vm = vm;
        vcpu->vcpu_id = i;

        vcpu->vcpu_state = VCPU_READY;

        vcpu->first_entry = true;

        vm->vcpus[i] = vcpu;

        printf("create vcpu with id %d\n", i);
    }

    vm->vm_state = VS_INIT;
    printf("vm: %d state: %d\n", vm->vm_id, vm->vm_state);
    return 0;
}

static void smc_realm_activate(kvm_smc_req_t* kvm_smc_req, unsigned long rd_addr)
{
    // change the state of specific realm to active
    struct s_visor_vm *kvm_vm =
            get_vm_by_id(kvm_smc_req->sec_vm_id);
    kvm_vm->vm_state = VS_READY;
    printf("vm: %d state: %d\n", kvm_vm->vm_id, kvm_vm->vm_state);
}

static void smc_realm_create(kvm_smc_req_t* kvm_smc_req, 
                             unsigned long rd_addr,
                             unsigned long realm_params_addr)
{
    // TODO: modify it, make it pass test
    printf("Boot realm vm with id %d\n", kvm_smc_req->sec_vm_id);
    struct s_visor_vm *kvm_vm =
        (struct s_visor_vm *)bd_alloc(sizeof(*kvm_vm), 0);
    uint64_t nr_vcpu = kvm_smc_req->boot.nr_vcpu;
    printf("init vm with vcpu %llu\n", nr_vcpu);
    only_init_empty_vm(kvm_vm, kvm_smc_req->sec_vm_id, "kvm_vm", nr_vcpu);
    kvm_vm->s2mmu = create_stage2_mmu();
    /* Get TTBR0 of QEMU */
    kvm_vm->qemu_s1ptp = kvm_smc_req->boot.qemu_s1ptp & (~0xFFFUL);
    
    s_visor_vm_enqueue(kvm_vm);
    printf("realm 0x%p created with id %d\n", kvm_vm, kvm_vm->vm_id);
}

// static void smc_realm_destroy(unsigned long rd_addr)
// {
//     // TODO: modify it, make it pass test
//     struct s_visor_vm *kvm_vm = get_vm_by_id(kvm_smc_req->sec_vm_id);

//     /* Update PMT checker info after shutdown */
//     rm_all_caches_from_vm(1, kvm_vm);
//     unsigned long top_pfn = get_top_pfn_of_all(1);
//     update_top_pfn(1, top_pfn);

//     s_visor_vm_dequeue(kvm_vm);
//     printf("kvm %p dequeued with id %d\n", kvm_vm, kvm_vm->vm_id);
//     destroy_stage2_mmu(kvm_vm->s2mmu);
//     destroy_kvm_vm(kvm_vm, PHYSICAL_CORE_NUM);
//     bd_free(kvm_vm);
// }

static void smc_rec_create(kvm_smc_req_t *kvm_smc_req,
                           unsigned long rec_addr,
                           unsigned long rd_addr,
                           unsigned long rec_params_addr)
{
    // TODO: modify it, make it pass test
    struct s_visor_vm *kvm_vm =
            get_vm_by_id(kvm_smc_req->sec_vm_id);
    only_init_empty_vcpu(kvm_vm);
}

// unsigned long smc_rec_destroy(unsigned long rec_addr)
// {
//     // TODO: modify it, make it pass test
//     bd_free(vm->vcpus[i]);
// }

static void rmm_smc_handler(kvm_smc_req_t *kvm_smc_req,
                            uint64_t smc_id, uint64_t x1,
                            uint64_t x2, uint64_t x3,
                            uint64_t x4)
{
    // TODO: implement this
    switch (smc_id)
    {
    case SMC_RMM_REALM_ACTIVATE:{
        smc_realm_activate(kvm_smc_req, x1);
        printf("smc_rmm_realm_activate\n");
        break;
    }
    case SMC_RMM_REALM_CREATE:{
        smc_realm_create(kvm_smc_req, x1, x2);
        printf("smc_rmm_realm_create\n");
        break;
    }
    case SMC_RMM_REALM_DESTROY:{
        uint32_t vm_id = kvm_smc_req->sec_vm_id;
        printf("smc_rmm_realm_destroy: vm_id: %u\n", vm_id);
        break;
    }
    case SMC_RMM_REC_CREATE:{
        smc_rec_create(kvm_smc_req, x1, x2, x3);
        printf("smc_rmm_rec_create\n");
        break;
    }
    case SMC_RMM_REC_DESTROY:{
        uint32_t vm_id = kvm_smc_req->sec_vm_id;
        uint32_t vcpu_id = kvm_smc_req->vcpu_id;
        printf("smc_rmm_rec_destroy: vm_id: %u, vcpu_id: %u\n", vm_id, vcpu_id);
        break;
    }
    default:
        break;
    }
}

void kvm_shared_memory_register(uint64_t smc_id, uint64_t x1)
{
    uint64_t shared_register_pages_local;
    if (!shared_register_pages)
    {
        shared_register_pages_local = x1;
        shared_register_pages = (uint64_t *)shared_register_pages_local;
        printf("%s: %d shared memory addr is 0x%p.\n", __func__, __LINE__,
               shared_register_pages);
    }
    else
    {
        printf("%s: %d shared memory already set up 0x%lx, addr %p\n", __func__, __LINE__, (unsigned long)shared_register_pages, &shared_register_pages);
    }
}

unsigned long kvm_shared_memory_handle(uint64_t smc_id, uint64_t x1,
                                       uint64_t x2, uint64_t x3, 
                                       uint64_t x4)
{
    uint64_t core_id = __get_core_pos();
    kvm_smc_req_t *kvm_smc_req = get_smc_req_region(core_id);
    // printf("%s: %d core_id: %d, smc_id: %lu, x1: %lx, x2: %lx, x3: %lx, x4: %lx\n", __func__, __LINE__, core_id, smc_id, x1, x2, x3, x4);
    switch (kvm_smc_req->req_type)
    {
    case REQ_KVM_TO_S_VISOR_REMAP_IPA:
    {
        struct s_visor_vm *kvm_vm =
            get_vm_by_id(kvm_smc_req->sec_vm_id);
        kvm_vm->migrated = 1;
        uint64_t src_start_pfn = kvm_smc_req->remap_ipa.src_start_pfn;
        uint64_t dst_start_pfn = kvm_smc_req->remap_ipa.dst_start_pfn;
        uint64_t *ipn_list = kvm_smc_req->remap_ipa.ipn_list;
        uint64_t nr_pages = kvm_smc_req->remap_ipa.nr_pages;

        for (int i = 0; i < nr_pages; i++)
        {
            s2mmu_map_page_invalid(kvm_vm->s2mmu,
                                   *(ipn_list + i) << PAGE_SHIFT,
                                   (dst_start_pfn + i) << PAGE_SHIFT, 1,
                                   MMU_ATTR_PAGE_RWE);
        }

        flush_dcache_and_tlb();

        /* PMT checker: keep src and dst cache safe  */
        unsigned long top_pfn = 0;
        if (!pfn_belongs_to_vm(kvm_vm, src_start_pfn))
        {
            printf("Vicious N-visor tries to assign cache to another vm.\n");
            hyp_panic();
        }
        else
        {
            /* PMT checker: update pool top */
            struct vm_cache *cache = NULL;
            uint64_t base_pfn = src_start_pfn;
            for_each_in_list(cache, struct vm_cache,
                             node_for_list, &kvm_vm->cache_list)
            {
                if (base_pfn == cache->base_pfn)
                    break;
            }
            rm_cache_from_vm(kvm_vm, cache);
            set_cache_free(1, base_pfn);
            bd_free((void *)cache);
            top_pfn = get_top_pfn_of_all(1);
            if (top_pfn < dst_start_pfn + (1 << 23 >> 12))
            {
                top_pfn = dst_start_pfn + (1 << 23 >> 12);
            }
            update_top_pfn(1, top_pfn);
        }
        int val_ret = validate_pfn(1, dst_start_pfn);
        if (val_ret != PFN_SEC_FREE && val_ret != PFN_NON_SEC)
        {
            printf("validate ret %d, dst start 0x%llx, top 0x%lx\n", val_ret, dst_start_pfn, top_pfn);
            hyp_panic();
        }

        /* Sync migration data */
        memcpy((void *)((uint64_t)dst_start_pfn << PAGE_SHIFT),
               (void *)((uint64_t)src_start_pfn << PAGE_SHIFT),
               nr_pages * PAGE_SIZE);
        update_vring_after_migrate(kvm_vm,
                                   dst_start_pfn,
                                   src_start_pfn);
        break;
    }
    case REQ_KVM_TO_S_VISOR_BOOT:
    {
        if (smc_id <= SMC_RMM_RTT_SET_RIPAS && smc_id >= SMC_RMM_VERSION)
        {
            // printf("RMM SMC ID %d\n", smc_id);
            rmm_smc_handler(kvm_smc_req, smc_id, x1, x2, x3, x4);
            break;
        }

        printf("Boot kvm with id %d\n", kvm_smc_req->sec_vm_id);
        struct s_visor_vm *kvm_vm =
            (struct s_visor_vm *)bd_alloc(sizeof(*kvm_vm), 0);
        uint64_t nr_vcpu = kvm_smc_req->boot.nr_vcpu;

        printf("init vm with vcpu %llu\n", nr_vcpu);
        init_empty_vm(kvm_vm, kvm_smc_req->sec_vm_id, "kvm_vm", nr_vcpu);

        kvm_vm->s2mmu = create_stage2_mmu();
        /* Get TTBR0 of QEMU */
        kvm_vm->qemu_s1ptp = kvm_smc_req->boot.qemu_s1ptp & (~0xFFFUL);
        if (kvm_vm->qemu_s1ptp >> 48)
        {
            BUG("qemu s1ptp align failed\n");
        }

        s_visor_vm_enqueue(kvm_vm);
        printf("kvm 0x%p created with id %d\n", kvm_vm, kvm_vm->vm_id);
        break;
    }
    case REQ_KVM_TO_S_VISOR_SHUTDOWN:
    {
        struct s_visor_vm *kvm_vm = get_vm_by_id(kvm_smc_req->sec_vm_id);

        /* Update PMT checker info after shutdown */
        rm_all_caches_from_vm(1, kvm_vm);
        unsigned long top_pfn = get_top_pfn_of_all(1);
        update_top_pfn(1, top_pfn);

        s_visor_vm_dequeue(kvm_vm);
        printf("kvm %p dequeued with id %d\n", kvm_vm, kvm_vm->vm_id);

        destroy_stage2_mmu(kvm_vm->s2mmu);
        destroy_kvm_vm(kvm_vm, PHYSICAL_CORE_NUM);

        bd_free(kvm_vm);

        break;
    }
    case REQ_KVM_TO_S_VISOR_UPDATE_TOP:
    {
        /* PMT checker */
        if (!validate_top_pfn(1, kvm_smc_req->top_pfn))
        {
            printf("top checker prevent this operation\n");
            break;
        }
        else
        {
            printf("top check passed!!\n");
        }

        /* update tzc range */
        lock(&tzc_lock);
        if (cache_number_start == (kvm_smc_req->top_pfn << 12 >> 23))
        {
            // all cache are clear
            cache_number_end = cache_number_start - 1;
            flush_dcache_and_tlb();
            tzc_configure_region(0, 1, 0, 0, 0, 0);
            printf("all caches are clear, reset region\n");
        }
        else
        {
            cache_number_end = ((kvm_smc_req->top_pfn << 12 >> 23) - 1);
            flush_dcache_and_tlb();
            tzc_configure_region(1 << 0x0, 1, cache_number_start << 23,
                                 ((cache_number_end + 1) << 23) - 1, 0x3, 0x0);
            printf("region are set to start: 0x%lx, end 0x%lx.\n",
                   cache_number_start, cache_number_end);
        }
        unlock(&tzc_lock);
        printf("region top pfn are 0x%llx.\n", kvm_smc_req->top_pfn);
        break;
    }
    default:
    {
        printf("Unknown SMC request type %d\n", kvm_smc_req->req_type);
        hyp_panic();
    }
    }
    return REALM_SUCCESS;
}
