#include <mm/stage1_mmu.h>
#include <mm/buddy_allocator.h>
#include <virt/sel2.h>
#include <common/def.h>
#include <stdio.h>

/*
 * Operate on mappings in a stage-1 PT using normal memory.
 * If pfn == 0, map a new page (alloc or refcount++).
 * If pfn == ~0, try to unmap a page (refcount-- or free).
 * Otherwise, map a VFN to PFN, set refcount to 1.
 * Return: >= 0 for refcount (0 means should be freed), < 0 for errno
 * FIXME: only support 3-level stage-1 PT with 4K granule
 */
int s1pt_vfn_to_pfn(s1_ptp_t *s1ptp, vaddr_t vfn, paddr_t pfn, s1_pte_t *ptep) {
    s1_ptp_t *l1_table = s1ptp;
    
    s1_ptp_t *l2_table = NULL;
    s1_pte_t l1_entry;
    uint32_t l1_shift = (3 - 1) * PAGE_ORDER;
    uint32_t l1_index = (vfn >> l1_shift) & ((1UL << PAGE_ORDER) - 1);
    
    if (!l1_table) return -EINVAL;
    l1_entry = l1_table->ent[l1_index];
    if (IS_PTE_INVALID(l1_entry.pte)) {
        s1_ptp_t *next_ptp = (s1_ptp_t *)shadow_bd_alloc(PAGE_SIZE, PAGE_SHIFT);
        if (!next_ptp) {
            return -ENOMEM;
        }
        memset(next_ptp, 0, PAGE_SIZE);

        l1_entry.table.is_valid = 1;
        l1_entry.table.is_table = 1;
        l1_entry.table.NS = 1;
        /* Should use virt_to_phys if MMU is enabled */
        l1_entry.table.next_table_addr = ((uint64_t)next_ptp) >> PAGE_SHIFT;
        l1_table->ent[l1_index] = l1_entry;
    } else if (!IS_PTE_TABLE(l1_entry.pte)) {
        /* Huge page should be disabled */
        return -EINVAL;
    }
    l2_table = (s1_ptp_t *)((uint64_t)l1_entry.table.next_table_addr << PAGE_SHIFT);

    s1_ptp_t *l3_table = NULL;
    s1_pte_t l2_entry;
    uint32_t l2_shift = (3 - 2) * PAGE_ORDER;
    uint32_t l2_index = (vfn >> l2_shift) & ((1UL << PAGE_ORDER) - 1);
    
    if (!l2_table) return -EINVAL;
    l2_entry = l2_table->ent[l2_index];
    if (IS_PTE_INVALID(l2_entry.pte)) {
        s1_ptp_t *next_ptp = (s1_ptp_t *)shadow_bd_alloc(PAGE_SIZE, PAGE_SHIFT);
        if (!next_ptp) {
            return -ENOMEM;
        }
        memset(next_ptp, 0, PAGE_SIZE);

        l2_entry.table.is_valid = 1;
        l2_entry.table.is_table = 1;
        l2_entry.table.NS = 1;
        /* OK due to direct mapping */
        l2_entry.table.next_table_addr = ((uint64_t)next_ptp) >> PAGE_SHIFT;
        l2_table->ent[l2_index] = l2_entry;
    } else if (!IS_PTE_TABLE(l2_entry.pte)) {
        /* Huge page should be disabled */
        return -EINVAL;
    }
    l3_table = (s1_ptp_t *)((uint64_t)l2_entry.table.next_table_addr << PAGE_SHIFT);
    
    s1_pte_t l3_entry;
    uint32_t l3_shift = (3 - 3) * PAGE_ORDER;
    uint32_t l3_index = (vfn >> l3_shift) & ((1UL << PAGE_ORDER) - 1);
    int refcount = -1;

    if (!l3_table) return -EINVAL;
    l3_entry = l3_table->ent[l3_index];
    if (l3_entry.l3_page.is_valid) {
        if (l3_entry.l3_page.soft_reserved == 0xf) {
            refcount = 0xf;
            if (pfn != 0 && pfn != ~0 &&
                    l3_entry.l3_page.pfn != pfn) {
                printf("[Stage1 MMU] ref count overflow.\n");
                hyp_panic();
            }
            goto out;
        }
        /* Mapping already exists! */
        if (pfn == 0)
            /* Another shadow DMA buffer! ++refcount */
            refcount = ++l3_entry.l3_page.soft_reserved;
        else if (pfn == ~0UL)
            /* Free a shadow DMA buffer! --refcount */
            refcount = --l3_entry.l3_page.soft_reserved;
        else {
            /* Mapping conflict? Should not happen! */
            printf("[Stage1 MMU] mapping conflict.\n");
            hyp_panic();
        }
    } else {
#if 1
        if (pfn == ~0UL) {
            refcount = 0;
            goto out;
        }
#endif
        if (pfn == 0) {
            /* New anonymous shadow DMA buffer! */
            pfn = ((paddr_t)shadow_bd_alloc(PAGE_SIZE, PAGE_SHIFT) >> PAGE_SHIFT);
            if (!pfn) {
                printf("[Stage1 MMU] pfn is null.\n");
                hyp_panic();
            }
        }
        l3_entry.pte = 0;

        l3_entry.l3_page.is_valid = 1;
        l3_entry.l3_page.is_page = 1;
        l3_entry.l3_page.AttrIndx = 0x4;
        l3_entry.l3_page.AP = 0x1;
        l3_entry.l3_page.SH = 0x3;
        l3_entry.l3_page.AF = 1;
        l3_entry.l3_page.nG = 1;

        l3_entry.l3_page.pfn = pfn;

        l3_entry.l3_page.DBM = 1;
        l3_entry.l3_page.PXN = 1;
        l3_entry.l3_page.UXN = 1;

        /* Use it as a refcount! No shadow_dma_records anymore! */
        refcount = l3_entry.l3_page.soft_reserved = 1;
    }
out:
    if (ptep)
        *ptep = l3_entry;
    if (refcount < 0) {
        printf("[Stage1 MMU] refcount is negative.\n");
        hyp_panic();
    }
    if (!refcount)
        l3_entry.pte = 0;
    l3_table->ent[l3_index] = l3_entry;
    return refcount;
}

int map_vfn_to_pfn(s1_ptp_t *s1ptp, vaddr_t vfn, paddr_t pfn) {
    return s1pt_vfn_to_pfn(s1ptp, vfn, pfn, NULL);
}

int map_vfn(s1_ptp_t *s1ptp, vaddr_t vfn, s1_pte_t *shadow_ptep) {
    return s1pt_vfn_to_pfn(s1ptp, vfn, 0, shadow_ptep);
}

int unmap_vfn(s1_ptp_t *s1ptp, vaddr_t vfn, s1_pte_t *shadow_ptep) {
    return s1pt_vfn_to_pfn(s1ptp, vfn, ~0UL, shadow_ptep);
}
