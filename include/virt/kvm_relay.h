#pragma once

#include <virt/vm.h>
#include <stdint.h>
#include <stddef.h>


/* Return from KVM */
void sync_shadow_vring_R2T(struct s_visor_vm *current_vm);
void alloc_copy_shadow_dma_buffer(struct s_visor_vm *current_vm, 
        uint16_t ori_avail_idx, uint16_t qid);

/* Forward to KVM */
void decode_kvm_vm_exit(struct s_visor_state *state, uint64_t core_id);
void virtio_dispatcher(struct s_visor_state *state, unsigned long esr_el, 
        unsigned long fault_ipa, uint64_t core_id);
void sync_shadow_vring_T2R(struct s_visor_vm *current_vm, uint16_t qid);
void copy_free_shadow_dma_buffer(struct s_visor_vm *current_vm, 
        uint16_t *, uint16_t *, uint16_t qid);

/* KVM VM migration */
void update_vring_after_migrate(struct s_visor_vm *kvm_vm,
        uint64_t dst_start_pfn, uint64_t src_start_pfn);
