#include <virt/kvm_relay.h>
#include <virt/virtio_ring.h>
#include <virt/virtio_pci.h>
#include <virt/vmexit_def.h>
#include <virt/stage2_mmu.h>
#include <virt/sel2.h>
#include <mm/stage1_mmu.h>
#include <mm/mm.h>
#include <mm/buddy_allocator.h>
#include <common/lock.h>
#include <sysreg.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <arch_helpers.h>

#include <common/def.h>

#define SHADOW_HVN_OFFSET (0x800000UL)
extern volatile int s_vring_init;

struct lock big_hyp_lock[3];

extern void flush_tlb(void);
extern void flush_dcache(void);
extern void flush_dcache_and_tlb(void);

int init_big_hyp_lock(void) {
    lock_init(big_hyp_lock + 0);
    lock_init(big_hyp_lock + 1);
    lock_init(big_hyp_lock + 2);
    return 0;
}
static inline void flush_tlb_hvn(unsigned long vfn) {
    dsbishst();
    tlbivale2is(vfn);
    dsbish();
}

static int decode_hsr(unsigned long esr, 
        struct s_visor_vcpu *vcpu, int *is_write, int *len) {
    unsigned long rt;
    int access_size;
    int sign_extend;

    access_size = 1 << ((esr & ESR_ELx_SAS) >> ESR_ELx_SAS_SHIFT);
    if (access_size < 0)
        return access_size;

    *is_write = !!(esr & (ESR_ELx_WNR | ESR_ELx_S1PTW));
    sign_extend = esr & ESR_ELx_SSE;
    rt = (esr & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;

    *len = access_size;
    vcpu->mmio_decode.sign_extend = sign_extend;
    vcpu->mmio_decode.rt = rt;

    return 0;
}

void dma_T2R(struct s_visor_vm *current_vm, unsigned int num,
        struct vring_desc *desc, struct vring_avail *avail,
        uint16_t avail_idx) {
    int header_idx = avail->ring[avail_idx % num];
    int desc_idx = header_idx;
    struct s2mmu* s2mmu = current_vm->s2mmu; 
    for (;;) {
        paddr_t dma_gpa = desc[desc_idx].addr;
        unsigned int dma_len = desc[desc_idx].len;
        /* Translate GPA of guest DMA buffer to HPA */
        unsigned long s2pt_mask = ~(~((1UL << 48) - 1) | PAGE_MASK);
        ptp_t *s2ptp = (ptp_t *)(read_vsttbr() & s2pt_mask);
        if ((dma_gpa >> PAGE_SHIFT) & SHADOW_HVN_OFFSET) {
            printf("[DMA T2R] dma_gpa wrong hvn offset.\n");
            hyp_panic();
        }

        paddr_t start_ipn = dma_gpa >> PAGE_SHIFT;
        paddr_t end_ipn = ROUNDUP(dma_gpa + dma_len, PAGE_SIZE) >> PAGE_SHIFT;
        paddr_t cur_ipn = start_ipn;
        unsigned int length = dma_len;
        if (start_ipn == end_ipn) {
            printf("[DMA T2R] start_ipn and end ipn should not be the same.\n");
            hyp_panic();
        }

        while (cur_ipn < end_ipn) {
            s1_pte_t shadow_pte;
            int refcount = map_vfn((s1_ptp_t *)current_vm->qemu_s1ptp, 
                    cur_ipn | SHADOW_HVN_OFFSET, &shadow_pte);
            if (refcount <= 0) {
                printf("[DMA T2R] refcount should be positive.\n");
                hyp_panic();
            }
            flush_tlb_hvn(cur_ipn | SHADOW_HVN_OFFSET);

            /* Only copy forward if the request is WRITE */
            if (!(desc[desc_idx].flags & VRING_DESC_F_WRITE)) {
                void *shadow_buf = (void *)((uint64_t)shadow_pte.l3_page.pfn << PAGE_SHIFT);
                if (!shadow_buf) {
                    printf("[DMA T2R] shadow buffer is null.\n");
                    hyp_panic();
                }

                size_t offset, cur_len;
                if (cur_ipn == start_ipn) {
                    offset = dma_gpa & 0xfff;
                    cur_len = (end_ipn == (start_ipn + 1)) ?
                        dma_len : (PAGE_SIZE - offset);
                } else if (cur_ipn + 1 == end_ipn) {
                    offset = 0;
                    cur_len = length;
                } else {
                    offset = 0;
                    cur_len = PAGE_SIZE;
                }

                pte_t dma_pte = s2mmu_translate_page(s2mmu, s2ptp, cur_ipn);
                memcpy(shadow_buf + offset,
                        (void *)((uint64_t)dma_pte.l3_page.pfn << PAGE_SHIFT) + offset,
                        cur_len);
                length -= cur_len;
            }

            ++cur_ipn;
        }
        if (!(desc[desc_idx].flags & VRING_DESC_F_WRITE) && length) {
            printf("[DMA T2R] WRITE flag not consistent.\n");
            hyp_panic();
        }

        if (!(desc[desc_idx].flags & VRING_DESC_F_NEXT))
            break;
        desc_idx = desc[desc_idx].next;
    }
}

/* VM -> KVM: 1. allcoate shadow DMA buffer (normal) for KVM
 * 2. copy data from guest DMA buffer (secure) to shadow DMA buffer (normal)
 * if necessary
 */
void alloc_copy_shadow_dma_buffer(struct s_visor_vm *current_vm, 
        uint16_t ori_avail_idx, uint16_t qid) {
	unsigned int num = current_vm->vrings[qid]->num;
	struct vring_desc *desc = current_vm->vrings[qid]->desc;
	struct vring_avail *avail = current_vm->vrings[qid]->avail;
	
    /* Indices of new dma buffers are in avail[last_avail_idx, avail->idx] */
    uint16_t avail_idx = current_vm->last_avail_ids[qid];
    for (; avail_idx != ori_avail_idx; avail_idx++) {
        dma_T2R(current_vm, num, desc, avail, avail_idx);
    }
}

void dma_R2T(struct s_visor_vm *current_vm, unsigned int num,
        struct vring_desc *desc, struct vring_used *used,
        uint16_t used_idx) {
    uint16_t header_idx = used->ring[used_idx % num].id;
    uint16_t desc_idx = header_idx;
    struct s2mmu* s2mmu = current_vm->s2mmu;
    for (;;) {
        paddr_t dma_gpa = desc[desc_idx].addr;
        unsigned int dma_len = desc[desc_idx].len;
        /* Translate GPA of guest DMA buffer to HPA */
        unsigned long s2pt_mask = ~(~((1UL << 48) - 1) | PAGE_MASK);
        ptp_t *s2ptp = (ptp_t *)(read_vsttbr() & s2pt_mask);
        if ((dma_gpa >> PAGE_SHIFT) & SHADOW_HVN_OFFSET) {
            printf("[DMA R2T] wrong hvn offset.\n");
            hyp_panic();
        }

        paddr_t start_ipn = dma_gpa >> PAGE_SHIFT;
        paddr_t end_ipn = ROUNDUP(dma_gpa + dma_len, PAGE_SIZE) >> PAGE_SHIFT;
        paddr_t cur_ipn = start_ipn;
        unsigned int length = dma_len;
        if (start_ipn == end_ipn) {
            printf("[DMA R2T] start_ipn and end ipn should not be the same.\n");
            hyp_panic();
        }

        while (cur_ipn < end_ipn) {
            s1_pte_t shadow_pte;
            int refcount = unmap_vfn((s1_ptp_t *)current_vm->qemu_s1ptp, 
                    cur_ipn | SHADOW_HVN_OFFSET, &shadow_pte);
            if (refcount < 0) {
                printf("[DMA T2R] refcount should not be negative.\n");
                hyp_panic();
            }
            flush_tlb_hvn(cur_ipn | SHADOW_HVN_OFFSET);

            void *shadow_buf = (void *)((uint64_t)shadow_pte.l3_page.pfn << PAGE_SHIFT);
            if (!shadow_buf) {
                printf("[DMA R2T] shadow buffer is null.\n");
                hyp_panic();
            }

            /* Only copy back if the request is READ */
            if (!!(desc[desc_idx].flags & VRING_DESC_F_WRITE)) {
                if (!shadow_buf) {
                    printf("[DMA R2T] shadow buffer is null version 2.\n");
                    hyp_panic();
                }

                size_t offset, cur_len;
                if (cur_ipn == start_ipn) {
                    offset = dma_gpa & 0xfff;
                    cur_len = (end_ipn == (start_ipn + 1)) ?
                        dma_len : (PAGE_SIZE - offset);
                } else if (cur_ipn + 1 == end_ipn) {
                    offset = 0;
                    cur_len = length;
                } else {
                    offset = 0;
                    cur_len = PAGE_SIZE;
                }

                pte_t dma_pte = s2mmu_translate_page(s2mmu, s2ptp, cur_ipn);
                memcpy((void *)((uint64_t)dma_pte.l3_page.pfn << PAGE_SHIFT) + offset, 
                        shadow_buf + offset, cur_len);
                length -= cur_len;
            }
            /* Must free shadow_buf after use */
            if (!refcount)
                shadow_bd_free(shadow_buf);

            ++cur_ipn;
        }
        if (!!(desc[desc_idx].flags & VRING_DESC_F_WRITE) && length) {
            printf("[DMA R2T] WRITE flag not consistent.\n");
            hyp_panic();
        }

        if (!(desc[desc_idx].flags & VRING_DESC_F_NEXT))
            break;
        desc_idx = desc[desc_idx].next;
    }
}

/* KVM -> VM: 1. copy data from shadow DMA buffer (normal) to 
 * guest DMA buffer (secure) if necessary
 * 2. free shadow DMA buffer (normal)
 */
void copy_free_shadow_dma_buffer(struct s_visor_vm *current_vm, 
        uint16_t *shd_used_idx, uint16_t *shd_flags, uint16_t qid) {
	unsigned int num = current_vm->shadow_vrings[qid]->num;
    // 用来描述一段vring
	struct vring_desc *desc = current_vm->shadow_vrings[qid]->desc;
    // 正在使用的vring
	struct vring_used *used = current_vm->shadow_vrings[qid]->used;
	
    *shd_used_idx = used->idx;
    *shd_flags = used->flags;

    /* Indices of handled dma buffers are in used[last_used_idx, used->idx] */
    uint16_t used_idx = current_vm->last_used_ids[qid];
    uint16_t end_idx = *shd_used_idx;

    for (; used_idx != end_idx; used_idx++) {
        dma_R2T(current_vm, num, desc, used, used_idx);
    }
}

// vm destroy的调用
void update_vring_after_migrate(struct s_visor_vm *kvm_vm,
        uint64_t dst_start_pfn, uint64_t src_start_pfn) {
    paddr_t old_desc_hpa, old_avail_hpa, old_used_hpa;
    paddr_t hpa_gap = (src_start_pfn - dst_start_pfn) << PAGE_SHIFT;
    int i = 0;

    for (; i < 3; i++) {
        old_desc_hpa = (paddr_t)kvm_vm->vrings[i]->desc;
        old_avail_hpa = (paddr_t)kvm_vm->vrings[i]->avail;
        old_used_hpa = (paddr_t)kvm_vm->vrings[i]->used;

        if ((old_desc_hpa >> 23) == (src_start_pfn >> 11)) {
            kvm_vm->vrings[i]->desc = (void *)(old_desc_hpa - hpa_gap);
            kvm_vm->vrings[i]->avail = (void *)(old_avail_hpa - hpa_gap);
            kvm_vm->vrings[i]->used = (void *)(old_used_hpa - hpa_gap);
        }
    }
}

void virtio_dispatcher(struct s_visor_state *state, 
        unsigned long esr_el, unsigned long fault_ipa, 
        uint64_t vcpu_id) {
    struct s_visor_vcpu *vcpu = state->current_vm->vcpus[vcpu_id];
    unsigned long data, rt;
    int is_write, len;
    if (decode_hsr(esr_el, vcpu, &is_write, &len)) {
        printf("[VIRTIO] decode hsr error.\n");
        hyp_panic();
    }

    rt = vcpu->mmio_decode.rt;
    /* KVM_EXIT_MMIO -> virtio_ioport_write */
    if ((fault_ipa >> PAGE_SHIFT) == 0x3eff1 && is_write) {
        unsigned long mask = (1UL << (len * 8)) - 1;

        data = state->guest_state->fastpath_ctx->x[rt] & mask;
        switch (fault_ipa & 0xff) {
            /* Find 0x3eff1008 for BLK by printing MMIO address in KVM,
             * 0x3eff1088 for NET
             */
            case 0x8: 
            case 0x88: {
                printf("[VIRTIO] data address: %llx\n", (void*)data);

                if (s_vring_init == 0) {
                    printf("init s_vring MEM [0x9000000000, 0x940000000)\n");
                    // 给shadow vring分配内存
                    shadow_bd_init();
                    // 初始化hyp lock
                    init_big_hyp_lock();
                    s_vring_init = 1;
                }

                unsigned long s2pt_mask = ~(~((1UL << 48) - 1) | PAGE_MASK);
                ptp_t *s2ptp = (ptp_t *)(state->current_vm->saved_s2mmu & s2pt_mask);

                pte_t desc_pte, avail_pte, used_pte;
                paddr_t desc_gpa, avail_gpa, used_gpa;

                /* FIXME: qid is actually set by QUEUE_SEL before QUEUE_PFN, 
                 * we just increase init_qid, assuming 0.BLK -> 1.RX -> 2.TX
                 */
                uint16_t qid = state->current_vm->init_qid;
                
                /* FIXME: Set in virtio_add_queue, hard-code here.
                 * BLK: 0x80, NET: 0x100
                 * 设置queue的大小
                 */
                if (qid)
                    state->current_vm->vqs[qid]->num = 0x100;
                else
                    state->current_vm->vqs[qid]->num = 0x80;

                /* Set number/size of vring for both guest & shadow vring */
                state->current_vm->vrings[qid]->num = 
                    state->current_vm->vqs[qid]->num;
                state->current_vm->shadow_vrings[qid]->num = 
                    state->current_vm->vqs[qid]->num;

                // 初始化vring
                vring_init(state->current_vm->vrings[qid], 
                        state->current_vm->vqs[qid]->num, 
                        (void *)(data << PAGE_SHIFT), PAGE_SIZE);

                // data是guest的vring的物理地址(GPA)
                desc_gpa = (paddr_t)state->current_vm->vrings[qid]->desc;
                avail_gpa = (paddr_t)state->current_vm->vrings[qid]->avail;
                used_gpa = (paddr_t)state->current_vm->vrings[qid]->used;

                printf("[VIRTIO] desc_gpa: %llx, avail_gpa: %llx, used_gpa: %llx\n", 
                        desc_gpa, avail_gpa, used_gpa);

                /* Translate GPA of guest vring to HPA */
                // 把guest physical address 转成host physical address
                desc_pte = translate_stage2_pt(s2ptp, desc_gpa >> PAGE_SHIFT);
                avail_pte = translate_stage2_pt(s2ptp, avail_gpa >> PAGE_SHIFT);
                used_pte = translate_stage2_pt(s2ptp, used_gpa >> PAGE_SHIFT);
                
                printf("[VIRTIO] desc_pte: %llx, avail_pte: %llx, used_pte: %llx\n", 
                        desc_pte, avail_pte, used_pte);

                /* Replace GPA of guest vring with HPA,
                 * S-visor can access guest vring due to direct mapping
                 */
                // 这一步就是把gpa后面的12位保留，前面部分换成hpa所属的page frame
                state->current_vm->vrings[qid]->desc = (void *)(
                        (desc_gpa & 0xfff) | desc_pte.l3_page.pfn << PAGE_SHIFT);
                state->current_vm->vrings[qid]->avail = (void *)(
                        (avail_gpa & 0xfff) | avail_pte.l3_page.pfn << PAGE_SHIFT);
                state->current_vm->vrings[qid]->used = (void *)(
                        (used_gpa & 0xfff) | used_pte.l3_page.pfn << PAGE_SHIFT);

                printf("[VIRTIO] vring: desc: %llx, avail: %llx, used: %llx\n", 
                        state->current_vm->vrings[qid]->desc, 
                        state->current_vm->vrings[qid]->avail, 
                        state->current_vm->vrings[qid]->used);

                /* Allocate shadow vring, then map to QEMU */
                unsigned int num = state->current_vm->shadow_vrings[qid]->num;
                // 获取shadow vring所需的内存大小
                unsigned int size = vring_size(num, PAGE_SIZE);
                // 从shadow vring的内存池中分配内存
                void *shadow_vring = shadow_bd_alloc(size, PAGE_SHIFT);
                printf("[VIRTIO] shadow_vring: address: %llx\n", shadow_vring);

                // 把shadow vring对应memory的值置为0
                memset(shadow_vring, 0, size);
                
                // 初始化shadow vring
                vring_init(state->current_vm->shadow_vrings[qid], num, 
                        shadow_vring, PAGE_SIZE);
                // 把current_vm vring的内容copy到shadow vring中
                memcpy(shadow_vring, state->current_vm->vrings[qid]->desc, size);

                // 判断一下SHAOW_HVN_OFFSET是否和gpa的page frame有重叠
                if ((desc_gpa >> PAGE_SHIFT) & SHADOW_HVN_OFFSET) {
                    printf("[VIRTIO] wrong hvn offset.\n");
                    hyp_panic();
                }

                /* The BLK vring has 128 (0x80 -> 8*16) entries, but the NET vring has 256 (0x100 -> 1*16*16) entries */
                int ret = 0, i = 0;
                paddr_t pfn = ((vaddr_t)shadow_vring >> PAGE_SHIFT);
                vaddr_t vfn = (desc_gpa >> PAGE_SHIFT) | SHADOW_HVN_OFFSET;
                printf("[VIRTIO] pfn: %llx, vfn: %llx\n", pfn, vfn);

                // 对每一页shadow vring page都进行映射
                // 对vfn和pfn进行映射
                for (; i < (ROUNDUP(size, PAGE_SIZE) >> PAGE_SHIFT); i++) {
                    ret = map_vfn_to_pfn((s1_ptp_t *)state->current_vm->qemu_s1ptp, 
                            vfn + i, pfn + i);
                    printf("map_vfn_to_pfn ret: %d\n", ret);
                    if (ret != 1) {
                        printf("[VIRTIO] map vfn to pfn failed.\n");
                        hyp_panic();
                    }
                    flush_tlb_hvn(vfn + i);
                }

                state->current_vm->init_qid++;

                // print information of vring and shadow_vring
                printf("[VIRTIO] qid: %u\n", qid);

                printf("[VIRTIO VA] desc: %p, avail: %p, used: %p\n", 
                        state->current_vm->vrings[qid]->desc, 
                        state->current_vm->vrings[qid]->avail, 
                        state->current_vm->vrings[qid]->used);
                printf("[VIRTIO PA] desc: %p, avail: %p, used: %p\n", 
                        virt_to_phys(state->current_vm->vrings[qid]->desc), 
                        virt_to_phys(state->current_vm->vrings[qid]->avail), 
                        virt_to_phys(state->current_vm->vrings[qid]->used));
                        
                printf("[VIRTIO] shadow desc: %p, shadow avail: %p, shadow used: %p\n",
                        state->current_vm->shadow_vrings[qid]->desc,
                        state->current_vm->shadow_vrings[qid]->avail,
                        state->current_vm->shadow_vrings[qid]->used);

                printf("[VIRTIO] shadow desc: %p, shadow avail: %p, shadow used: %p\n",
                        virt_to_phys(state->current_vm->shadow_vrings[qid]->desc),
                        virt_to_phys(state->current_vm->shadow_vrings[qid]->avail),
                        virt_to_phys(state->current_vm->shadow_vrings[qid]->used));

                break;
            }
            case VIRTIO_PCI_QUEUE_NUM: {
                printf("[VIRTIO] queue number not supported.\n");
                hyp_panic();
                break;
            }
            /* Find 0x3eff1010 is for VIRTIO-BLK */
            case 0x10: {
                uint16_t qid = 0;
                /* If guest VM writes MMIO region of VIRTIO-BLK, sync shadow vring
                 */
                sync_shadow_vring_T2R(state->current_vm, qid);
                break;
            }
            /* Find 0x3eff1090 is for VIRTIO-NET, qid 1 for RX, 2 for TX */
            case 0x90: {
                uint16_t qid = (data == 0) ? 1 : 2;
                /* If guest VM writes MMIO region of VIRTIO-NET, sync shadow vring
                 */
                sync_shadow_vring_T2R(state->current_vm, qid);
                break;
            }
            default:
                break;
        }
    }
}

uint16_t update_shadow_desc_avail_step1(struct s_visor_vm *current_vm,
        uint16_t *ori_avail_idx, uint16_t *ori_flags, uint16_t qid) {
	unsigned int num = current_vm->vrings[qid]->num;
	struct vring_desc *shadow_desc = current_vm->shadow_vrings[qid]->desc;
	struct vring_desc *original_desc = current_vm->vrings[qid]->desc;
	struct vring_avail *shadow_avail = current_vm->shadow_vrings[qid]->avail;
	struct vring_avail *original_avail = current_vm->vrings[qid]->avail;
	unsigned short *shadow_avail_ring = shadow_avail->ring;
	unsigned short *original_avail_ring = original_avail->ring;

    *ori_avail_idx = original_avail->idx;
    *ori_flags = original_avail->flags;

    /* BLK: 0x80 - 1, NET: 0x100 - 1 */
    uint16_t q_mask = (qid == 0) ? 0x7f : 0xff;

    uint16_t avail_idx = current_vm->last_avail_ids[qid];
    uint16_t end_idx = *ori_avail_idx;
    if (avail_idx > end_idx &&
            (avail_idx - end_idx <= q_mask)) {
        printf("[VIRTIO AVAIL 1] wrong virtio index.\n");
        hyp_panic();
    }

    // copy vring to normal world
    for (; avail_idx != end_idx; avail_idx++) {
        uint16_t header_idx = original_avail_ring[avail_idx % num];
        uint16_t desc_idx = header_idx;
        
        for (;;) {
            shadow_desc[desc_idx] = original_desc[desc_idx];
            if (!(original_desc[desc_idx].flags & VRING_DESC_F_NEXT)) {
                break;
            }
            desc_idx = original_desc[desc_idx].next;
        }
        shadow_avail_ring[avail_idx % num] = original_avail_ring[avail_idx % num];
    }

    return *ori_avail_idx;
}

uint16_t update_shadow_desc_avail_step2(struct s_visor_vm *current_vm, 
        uint16_t ori_avail_idx, uint16_t ori_flags, uint16_t qid) {
	struct vring_avail *shadow_avail = current_vm->shadow_vrings[qid]->avail;
	struct vring_avail *original_avail = current_vm->vrings[qid]->avail;

    /* BLK: 0x80 - 1, NET: 0x100 - 1 */
    uint16_t q_mask = (qid == 0) ? 0x7f : 0xff;
    
    if (qid == 2)
        shadow_avail->flags = original_avail->flags;
    if (shadow_avail->idx <= ori_avail_idx ||
            /* 0xFFFF + 0x1 --> 0 */
            (shadow_avail->idx - ori_avail_idx  > q_mask)) {
        shadow_avail->idx = ori_avail_idx;

        /* Shadow buffers are ready now, 
         * update last_avail_idx to avail->idx 
         */
        current_vm->last_avail_ids[qid] = ori_avail_idx;
    } else if (shadow_avail->idx != ori_avail_idx) {
        printf("[VIRTIO AVAIL 2] wrong virtio index.\n");
        hyp_panic();
    }

    return original_avail->idx;
}

/* T2R: TEE to REE
 * If guest VM writes MMIO region of VIRTIO-BLK, sync shadow vring
 */
void sync_shadow_vring_T2R(struct s_visor_vm *current_vm, uint16_t qid) {
    lock(big_hyp_lock + qid);

    uint16_t ori_avail_idx, ori_flags;

    update_shadow_desc_avail_step1(current_vm, &ori_avail_idx, &ori_flags, qid);
    
    alloc_copy_shadow_dma_buffer(current_vm, ori_avail_idx, qid);
    update_shadow_desc_avail_step2(current_vm, ori_avail_idx, ori_flags, qid);
    
    unlock(big_hyp_lock + qid);
}

void update_shadow_used(struct s_visor_vm *current_vm, 
        uint16_t shd_used_idx, uint16_t shd_flags, uint16_t qid) {
	unsigned int num = current_vm->shadow_vrings[qid]->num;
	struct vring_used *shadow_used = current_vm->shadow_vrings[qid]->used;
	struct vring_used *original_used = current_vm->vrings[qid]->used;
	struct vring_used_elem *shadow_used_ring = shadow_used->ring;
	struct vring_used_elem *original_used_ring = original_used->ring;

    /* BLK: 0x80 - 1, NET: 0x100 - 1 */
    uint16_t q_mask = (qid == 0) ? 0x7f : 0xff;
    /* Indices of handled dma buffers are in used[last_used_idx, used->idx] */
    uint16_t used_idx = current_vm->last_used_ids[qid];
    uint16_t end_idx = shd_used_idx;
    if (used_idx > end_idx &&
            (used_idx - end_idx <= q_mask)) {
        printf("[VIRTIO USED] wrong virtio index.\n");
        hyp_panic();
    }
    
    // copy vring from normal world
    for (; used_idx != end_idx; used_idx++)
        original_used_ring[used_idx % num] = shadow_used_ring[used_idx % num];
    
    if (qid == 2)
        original_used->flags = shadow_used->flags;
    if (original_used->idx <= shd_used_idx ||
            /* 0xFFFF + 0x1 --> 0 */
            (original_used->idx - shd_used_idx > q_mask)) {
        original_used->idx = shd_used_idx;

        /* Update last_used_idx to used->idx */
        current_vm->last_used_ids[qid] = shd_used_idx;
    } else if (original_used->idx != shd_used_idx) {
        printf("[VIRTIO USED] wrong virtio index version 2.\n");
        hyp_panic();
    }
}

static inline int blk_need_sync(unsigned long lr0, unsigned long lr1, 
        unsigned long lr2, unsigned long lr3) {
    unsigned long mask = 0xffff;
    unsigned long virq = 0x24;
    if ((lr0 & mask) == virq || (lr1 & mask) == virq ||
            (lr2 & mask) == virq || (lr3 & mask) == virq)
        return 1;
    return 0;
}

static inline int rx_need_sync(unsigned long lr0, unsigned long lr1, 
        unsigned long lr2, unsigned long lr3) {
    unsigned long mask = 0xffff;
    unsigned long virq = 0x25;
    if ((lr0 & mask) == virq || (lr1 & mask) == virq ||
            (lr2 & mask) == virq || (lr3 & mask) == virq)
        return 1;
    return 0;
}

static inline int tx_need_sync(unsigned long lr0, unsigned long lr1, 
        unsigned long lr2, unsigned long lr3) {
    unsigned long mask = 0xffff;
    unsigned long virq = 0x26;
    if ((lr0 & mask) == virq || (lr1 & mask) == virq ||
            (lr2 & mask) == virq || (lr3 & mask) == virq)
        return 1;
    return 0;
}

void sync_blk_R2T(struct s_visor_vm *current_vm) {
        uint16_t qid = 0;
        lock(big_hyp_lock + qid);
        
        uint16_t shd_used_idx, shd_flags;
        copy_free_shadow_dma_buffer(current_vm, &shd_used_idx, &shd_flags, qid);

        update_shadow_used(current_vm, shd_used_idx, shd_flags, qid);
        
        unlock(big_hyp_lock + qid);
}

void sync_net_rx_R2T(struct s_visor_vm *current_vm) {
        uint16_t qid = 1;
        lock(big_hyp_lock + qid);
        
        uint16_t shd_used_idx, shd_flags;
        copy_free_shadow_dma_buffer(current_vm, &shd_used_idx, &shd_flags, qid);
        
        update_shadow_used(current_vm, shd_used_idx, shd_flags, qid);
        
        unlock(big_hyp_lock + qid);
}

void sync_net_tx_R2T(struct s_visor_vm *current_vm) {
        uint16_t qid = 2;
        lock(big_hyp_lock + qid);
        
        uint16_t shd_used_idx, shd_flags;
        copy_free_shadow_dma_buffer(current_vm, &shd_used_idx, &shd_flags, qid);
        
        update_shadow_used(current_vm, shd_used_idx, shd_flags, qid);
        
        unlock(big_hyp_lock + qid);
}

/* R2T: REE to TEE
 * If guest VM receives SPI [ID == 0x51], sync shadow vring before eret
 */
void sync_shadow_vring_R2T(struct s_visor_vm *current_vm) {
    // registers related to GIC
    unsigned long ich_lr0_el2 = read_sysreg_s(SYS_ICH_LR0_EL2);
    unsigned long ich_lr1_el2 = read_sysreg_s(SYS_ICH_LR1_EL2);
    unsigned long ich_lr2_el2 = read_sysreg_s(SYS_ICH_LR2_EL2);
    unsigned long ich_lr3_el2 = read_sysreg_s(SYS_ICH_LR3_EL2);

    int blk, net_rx, net_tx;

    blk = blk_need_sync(ich_lr0_el2, ich_lr1_el2, ich_lr2_el2, ich_lr3_el2);
    net_rx = rx_need_sync(ich_lr0_el2, ich_lr1_el2, ich_lr2_el2, ich_lr3_el2);
    net_tx = tx_need_sync(ich_lr0_el2, ich_lr1_el2, ich_lr2_el2, ich_lr3_el2);

    // 网络发送
    if (net_tx)
        sync_net_tx_R2T(current_vm);
    
    // 网络接收
    if (net_rx)
        sync_net_rx_R2T(current_vm);

    // blk
    if (blk)
        sync_blk_R2T(current_vm);
}


/* KVM VM exit, check if memory or MMIO abort */
void decode_kvm_vm_exit(struct s_visor_state *state, uint64_t vcpu_id) {
    unsigned long esr_el = read_esr_el2();
    uint64_t kvm_exit_reason = ESR_EL_EC(esr_el);
    unsigned long fault_ipn = (read_hpfar_el2() >> 4);

    if (kvm_exit_reason == ESR_ELx_EC_IABT_LOW || 
            kvm_exit_reason == ESR_ELx_EC_DABT_LOW) {
        // FIXME: discern device address fault from memory fault
        if (fault_ipn >= 0x40000 && fault_ipn < 0x80000) {
            state->current_vm->vcpus[vcpu_id]->is_s2pt_violation = 1;
            state->current_vm->vcpus[vcpu_id]->fault_ipn = fault_ipn;
        }
    }
    /* Following conditions will lead to *io_mem_abort* in KVM 
     * (ESR_EL & ESR_EL_WNR) || (ESR_EL * ESR_EL_S1PTW), i.e. bit 6/7
     */
    if (kvm_exit_reason == ESR_ELx_EC_DABT_LOW) {
        virtio_dispatcher(state, esr_el, 
                (fault_ipn << PAGE_SHIFT) | (read_far_el2() & 0xfff),
                vcpu_id);
    }
}

