#include <common/errno.h>
#include <common/list.h>
#include <common/def.h>
#include <common/md5.h>
#include <common/image_md5_data.h>
#include <virt/vm.h>
#include <virt/vcpu.h>
#include <virt/stage2_mmu.h>
#include <virt/stage2_mmu_def.h>
#include <virt/vmexit_def.h>
#include <virt/virtio_ring.h>
#include <virt/kvm_relay.h>
#include <virt/sel2.h>
#include <virt/vm_handler.h>
#include <mm/buddy_allocator.h>
#include <mm/stage1_mmu.h>
#include <mm/mm.h>
#include <mm/tzc400.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <arch_helpers.h>

const unsigned long cache_number_min = 0x880000000 >> 23;
const unsigned long cache_number_max = 0x8c0000000 >> 23;
unsigned long cache_number_start = 0x1100UL;
unsigned long cache_number_end = 0x1100UL - 1;
struct list_head s_visor_vm_list;
struct s_visor_state global_s_visor_states[PHYSICAL_CORE_NUM];
extern struct lock tzc_lock;
void flush_dcache_and_tlb(void);

/**
 * Set up a initial register stages for guest VCPU
 */
void init_vms(void) {
    /* Init vm list which holds all VM in s_visor */
    list_init(&s_visor_vm_list);
    mem_pools[1].start_pfn = (34UL << 30) >> 12;
    mem_pools[1].cur_top_pfn = (34UL << 30) >> 12;
    mem_pools[1].end_pfn = (35UL << 30) >> 12;
    init_bitmap(1);
}

/**
 * Traverse s_visor_vm_list and find target VM by @vm_id
 */
struct s_visor_vm *get_vm_by_id(int vm_id) {
    struct s_visor_vm *vm = NULL;
    for_each_in_list(vm, struct s_visor_vm, vm_list_node, &s_visor_vm_list) {
        if (vm->vm_id == vm_id)
            return vm;
    }
    return NULL; //not found
}

static inline void save_current_el1_sys_regs(struct s_visor_vcpu *state) {
    unsigned long sys_reg_kvm;
    asm volatile("mrs %0, spsr_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.spsr = sys_reg_kvm; 
    
    asm volatile("mrs %0, elr_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.elr = sys_reg_kvm; 
    
    asm volatile("mrs %0, sctlr_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.sctlr = sys_reg_kvm; 
    
    asm volatile("mrs %0, sp_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.sp = sys_reg_kvm; 
    
    asm volatile("mrs %0, sp_el0 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.sp_el0 = sys_reg_kvm; 
    
    asm volatile("mrs %0, esr_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.esr = sys_reg_kvm;
    
    asm volatile("mrs %0, vbar_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.vbar = sys_reg_kvm; 
    
    asm volatile("mrs %0, ttbr0_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.ttbr0 = sys_reg_kvm; 
    
    asm volatile("mrs %0, ttbr1_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.ttbr1 = sys_reg_kvm; 
    
    asm volatile("mrs %0, mair_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.mair = sys_reg_kvm; 
    
    asm volatile("mrs %0, amair_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.amair = sys_reg_kvm; 
    
    asm volatile("mrs %0, tcr_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.tcr = sys_reg_kvm; 
    
    asm volatile("mrs %0, tpidr_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.tpidr = sys_reg_kvm; 

    asm volatile("mrs %0, actlr_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.actlr = sys_reg_kvm; 

    asm volatile("mrs %0, tpidr_el0 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.tpidr_el0 = sys_reg_kvm; 

    asm volatile("mrs %0, tpidrro_el0 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.tpidrro = sys_reg_kvm; 

    asm volatile("mrs %0, vmpidr_el2 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.mpidr = sys_reg_kvm; 

    asm volatile("mrs %0, csselr_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.csselr= sys_reg_kvm; 

    asm volatile("mrs %0, cpacr_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.cpacr = sys_reg_kvm; 

    asm volatile("mrs %0, afsr0_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.afsr0 = sys_reg_kvm; 

    asm volatile("mrs %0, afsr1_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.afsr1 = sys_reg_kvm; 

    asm volatile("mrs %0, far_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.far = sys_reg_kvm; 

    asm volatile("mrs %0, cntkctl_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.cntkctl = sys_reg_kvm; 

    asm volatile("mrs %0, par_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.par = sys_reg_kvm; 

    asm volatile("mrs %0, contextidr_el1 \n":"=r"(sys_reg_kvm));
    state->current_vcpu_ctx.sys_regs.contextidr = sys_reg_kvm; 
}

/*
 * Check whether KVM's upates to @vm are dangerous
 */
static void check_vm_state(struct s_visor_vcpu *state) {
    unsigned long sys_reg_kvm;

    // save el1 sys regs only when first enter guest
    if (state->first_entry) {
        save_current_el1_sys_regs(state);
        state->first_entry = false;
    }
    // check nothing for irq vm exit since it exposes nothing 
    if (!state->is_sync_trap) {
        return;
    }

    unsigned long esr = state->current_vcpu_ctx.hyp_regs.esr;
    int reason = ESR_EL_EC(esr);

    // el1 sys regs write trap
    if (reason == ESR_ELx_EC_SYS64 && !(esr & 1)) {
        unsigned int sys_reg_no = sys_reg(
                (esr >> 20) & 0x3,
                (esr >> 14) & 0x7,
                (esr >> 10) & 0xf,
                (esr >> 1 ) & 0xf,
                (esr >> 17) & 0x7);
        switch (sys_reg_no) {
            case sys_reg(3, 0, 1, 0, 0):
                asm volatile("mrs %0, sctlr_el1 \n":"=r"(sys_reg_kvm));
                state->current_vcpu_ctx.sys_regs.sctlr = sys_reg_kvm; 
                break;
            case sys_reg(3, 0, 2, 0, 0):
                asm volatile("mrs %0, ttbr0_el1 \n":"=r"(sys_reg_kvm));
                state->current_vcpu_ctx.sys_regs.ttbr0 = sys_reg_kvm; 
                break;
            case sys_reg(3, 0, 2, 0, 1):
                asm volatile("mrs %0, ttbr1_el1 \n":"=r"(sys_reg_kvm));
                state->current_vcpu_ctx.sys_regs.ttbr1 = sys_reg_kvm; 
                break;
            case sys_reg(3, 0, 2, 0, 2):
                asm volatile("mrs %0, tcr_el1 \n":"=r"(sys_reg_kvm));
                state->current_vcpu_ctx.sys_regs.tcr = sys_reg_kvm; 
                break;
            case sys_reg(3, 0, 10, 2, 0):
                asm volatile("mrs %0, mair_el1 \n":"=r"(sys_reg_kvm));
                state->current_vcpu_ctx.sys_regs.mair = sys_reg_kvm; 
                break;
            case sys_reg(3, 0, 10, 3, 0):
                asm volatile("mrs %0, amair_el1 \n":"=r"(sys_reg_kvm));
                state->current_vcpu_ctx.sys_regs.amair = sys_reg_kvm; 
                break;
            default:
                break;
        }
    }
    // el1 sys regs read trap
    if (reason == ESR_ELx_EC_SYS64 && (esr & 1)) { 
        int rt = (esr & ESR_ELx_SYS64_ISS_RT_MASK) 
            >> ESR_ELx_SYS64_ISS_RT_SHIFT;
        state->current_vcpu_ctx.gp_regs.x[rt] = state->fastpath_ctx->x[rt];
    }
    // handle hvc call for psci
    if (reason == ESR_ELx_EC_HVC64 || reason == ESR_ELx_EC_HVC32) { 
        memcpy((void *)&state->current_vcpu_ctx.gp_regs,
            (void *)state->fastpath_ctx, 
            4 * 8); // copy a0, 1, a2, a3 
    }
    // handle mmio
    if ((reason == ESR_ELx_EC_IABT_LOW || reason == ESR_ELx_EC_DABT_LOW) && !(esr & ESR_ELx_WNR)) { 
        unsigned long fault_ipn = (state->current_vcpu_ctx.hyp_regs.hpfar >> 4);
        if (fault_ipn < (GPA_START >> 12) || fault_ipn >= ((GPA_START + GPA_LENGTH) >> 12)) {
            int rt = (esr & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;
            state->current_vcpu_ctx.gp_regs.x[rt] = state->fastpath_ctx->x[rt];
        }
    }
}

/*
 * expose certain SVM state to KVM of @vm
 */
static void expose_vm_state(struct s_visor_vcpu *state, int exit_reason) {
    if (exit_reason == S_VISOR_VMEXIT_FIQ) {
        state->is_sync_trap = 0;
        return;
    } else {
        state->is_sync_trap = 1;
    }
    unsigned long esr = state->current_vcpu_ctx.hyp_regs.esr;
    int reason = ESR_EL_EC(esr);

    // el1 sys regs write trap
    if (reason == ESR_ELx_EC_SYS64 && !(esr & 1)) { 
        int rt = (esr & ESR_ELx_SYS64_ISS_RT_MASK) 
            >> ESR_ELx_SYS64_ISS_RT_SHIFT;
        state->fastpath_ctx->x[rt] = state->current_vcpu_ctx.gp_regs.x[rt];
    }

    // hvc call for psci
    if (reason == ESR_ELx_EC_HVC64 || reason == ESR_ELx_EC_HVC32) { 
        memcpy((void *)state->fastpath_ctx,
            (void *)&state->current_vcpu_ctx.gp_regs, 4 * 8); // copy a0, a1, a2, a3 
    }

    if ((reason == ESR_ELx_EC_IABT_LOW || reason == ESR_ELx_EC_DABT_LOW)) {
        unsigned long fault_ipn = (state->current_vcpu_ctx.hyp_regs.hpfar >> 4);
        if (fault_ipn < (GPA_START >> 12) || fault_ipn >= ((GPA_START + GPA_LENGTH) >> 12)) {
            int rt = (esr & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;
            state->fastpath_ctx->x[rt] = state->current_vcpu_ctx.gp_regs.x[rt];
        }
    }
}

static void check_kernel_integrity(struct s_visor_vm *vm, paddr_t fault_ipn, paddr_t fault_pa) {
    if (vm->migrated)
        return;
    unsigned long md5_value[2];
    unsigned long offset = fault_ipn - KERNEL_IPN_START;
    unsigned long len;
    if (fault_ipn >= KERNEL_IPN_START && fault_ipn < KERNEL_IPN_START + PAGE_UPPER(IMAGE_SIZE)) {
        MD5_CTX md5;
        MD5Init(&md5);
        len = (fault_ipn == KERNEL_IPN_START + PAGE_UPPER(IMAGE_SIZE) - 1 ?
                IMAGE_SIZE % PAGE_SIZE : PAGE_SIZE);
        MD5Update(&md5, (unsigned char *)fault_pa, len);
        MD5Final(&md5, (unsigned char *)md5_value);

        if (md5_value[0] != image_md5_per_page[offset][0] &&
            md5_value[1] != image_md5_per_page[offset][1]) {
            printf("offset is %lx, correct md5 %lx %lx, computed md5 is %lx %lx, ptr1 %p, ptr2 %p\n",
                    offset, md5_value[0], md5_value[1], 
                    image_md5_per_page[offset][0], 
                    image_md5_per_page[offset][1],
                    &image_md5_per_page[offset][0], 
                    &image_md5_per_page[offset][1]);
            hyp_panic();
        }
    }
}


/* Sync 1 PTE from vttbr to vsttbr */
static void sync_vttbr_to_vsttbr(struct s_visor_vm *target_vm, uint64_t vcpu_id) {
    paddr_t fault_ipn = target_vm->vcpus[vcpu_id]->fault_ipn;
    target_vm->vcpus[vcpu_id]->is_s2pt_violation = 0;

    paddr_t vttbr_value = read_vttbr();
    unsigned long s2pt_mask = ~(~((1UL << 48) - 1) | PAGE_MASK);

    pte_t target_pte;
    ptp_t *s2ptp = (ptp_t *)(vttbr_value & s2pt_mask);
    target_pte = translate_stage2_pt(s2ptp, fault_ipn);

    /* 
     * adjust the address range of secure memory region 
     * Filter: FVP only supports #0 (for CPU) and #2
     * Region: DRAM1 & DRAM2 occupy #1 - #2, we start from #3
     * Secure attribute: bit 0 is s_rd_en, bit 1 is s_wr_en
     * NSAID: refer to ATF
     * 
     * Range: [0x880000, 0x8c0000)
     * FIXME: remove the hard code
     */
    unsigned long cache_number = target_pte.l3_page.pfn << 12 >> 23;
    if (cache_number >= cache_number_min && cache_number < cache_number_max) {
        int modify_region_flag = 0;
        lock(&tzc_lock);
        if (cache_number < cache_number_start) {
            cache_number_start = cache_number;
            modify_region_flag = 1;
        }
        if (cache_number > cache_number_end) {
            cache_number_end = cache_number;
            modify_region_flag = 1;
        }
        if (modify_region_flag) {
            flush_dcache_and_tlb();
            tzc_configure_region(1 << 0x0, 1, cache_number_start << 23, 
                    ((cache_number_end + 1) << 23) - 1, 0x3, 0x0);
        }
        unlock(&tzc_lock);
        if (modify_region_flag) {
            printf("start: 0x%lx, end: 0x%lx\n", cache_number_start, cache_number_end);
        }
    } else {
        printf("[TZASC] Invalid current_pfn, 0x%lx\n", cache_number);
    }

    if (target_pte.l3_page.is_valid) {
        s2mmu_map_page(target_vm->s2mmu, fault_ipn << PAGE_SHIFT, 
                target_pte.l3_page.pfn << PAGE_SHIFT, 1, 
                MMU_ATTR_PAGE_RWE);
        // check_kernel_integrity(target_vm, fault_ipn, target_pte.l3_page.pfn << PAGE_SHIFT);


        /* Security check using PMT */
        unsigned long base_pfn = target_pte.l3_page.pfn & ~(0x7ff);
        int val = validate_pfn(1, base_pfn);
        if (val == PFN_NON_SEC || val == PFN_SEC_FREE) {
            struct vm_cache *cache = bd_alloc(sizeof(struct vm_cache), 0);
            cache->base_pfn = base_pfn;
            add_cache_to_vm(target_vm, cache);
            set_cache_used(1, base_pfn);
            printf("val %d, base_pfn 0x%llx, target_vm %p\n", val, cache->base_pfn, target_vm);
            if (mem_pools[1].cur_top_pfn <= cache->base_pfn) {
                if (mem_pools[1].cur_top_pfn != cache->base_pfn) {
                    printf("[PMT checker] warning, cache jump.\n");
                    mem_pools[1].cur_top_pfn = cache->base_pfn + 0x800;
                } else
                    mem_pools[1].cur_top_pfn = cache->base_pfn + 0x800;
            }
        } else if (val == PFN_IN_USE) {
            if (!pfn_belongs_to_vm(target_vm, base_pfn)) {
                printf("[PMT checker] N-visor tries to map cache already in use.\n");
                hyp_panic();
            }
        } if (val == PFN_INVALID) {
            printf("[PMT checker] N-visor tries to map cache outside the range of split CMA.\n");
            hyp_panic();
        }

    } else {
        printf("[VSTTBR] Invalid current_pfn, 0x%lx\n", (unsigned long)target_pte.l3_page.pfn);
        hyp_panic();
    }

}

/* forward smc request to the corresponding VM */
static unsigned long f_count = 1;
int forward_smc_to_vm() {
    // printf("forward_smc_to_vm [%lu]\n", f_count);
    struct s_visor_vm *target_vm = NULL;
    struct s_visor_vcpu *target_vcpu = NULL; 
    struct s_visor_state *state = NULL;
    uint64_t core_id = __get_core_pos();
    uint64_t vcpu_id = ~0;
    kvm_smc_req_t* kvm_smc_req = NULL;

    kvm_smc_req = get_smc_req_region(core_id); 
    vcpu_id = kvm_smc_req->vcpu_id;
    target_vm = get_vm_by_id(kvm_smc_req->sec_vm_id);
    if (target_vm == NULL) {
        printf("target vm %d is null", kvm_smc_req->sec_vm_id);
        hyp_panic();
    }
    if (target_vm->nr_vcpu <= vcpu_id) {
        printf("vcpu_id: %llu nr_vcpu: %d\n", vcpu_id, target_vm->nr_vcpu);
        printf("vcpu_id should be less than the number of vcpu");
        hyp_panic();
    }
    target_vcpu = target_vm->vcpus[vcpu_id];

    /* sync globlal_s_visor with target_vcpu */
    state = &global_s_visor_states[core_id];
    state->guest_state = target_vcpu;
    state->current_vm = target_vm;
    
    target_vcpu->fastpath_ctx = (struct gp_regs *) get_gp_reg_region(core_id);

    paddr_t vttbr_value = read_vttbr();
    unsigned long s2pt_mask = ~(~((1UL << 48) - 1) | PAGE_MASK);

    if (target_vcpu->is_s2pt_violation) {
        sync_vttbr_to_vsttbr(target_vm, vcpu_id);
    }
    write_vsttbr((paddr_t)target_vm->s2mmu->pgtbl | 
            (vttbr_value & ~s2pt_mask));
    target_vm->saved_s2mmu = read_vsttbr();

    sync_shadow_vring_R2T(target_vm);

    check_vm_state(target_vcpu);
    if (f_count % 1000 == 0) 
    {
        printf("enter_guest [%lu]\n", f_count);
    }
    
    f_count = f_count + 1;
    int ret = enter_guest();
    expose_vm_state(target_vcpu, ret);
    // printf("exit reason [%d]\n", ret);

    if (ret == S_VISOR_VMEXIT_SYNC)
        decode_kvm_vm_exit(&global_s_visor_states[core_id], vcpu_id);

    uint64_t kvm_exit_reason = ESR_EL_EC(read_esr_el2());
    if (ret == S_VISOR_VMEXIT_IRQ ||
            (ret == S_VISOR_VMEXIT_SYNC &&
             kvm_exit_reason == ESR_ELx_EC_WFx)) {
        if (state->current_vm->init_qid == 3) {
            extern void sync_net_tx_R2T(struct s_visor_vm *current_vm);
            sync_net_tx_R2T(state->current_vm);

            extern void sync_net_rx_R2T(struct s_visor_vm *current_vm);
            sync_net_rx_R2T(state->current_vm);
        }
    }
    
    state->current_vm->vm_state = VS_READY;
    state->current_vm->vcpus[vcpu_id]->vcpu_state = VCPU_READY;

    // printf("back to kvm [%d]\n", ret);
    return ret;
}
