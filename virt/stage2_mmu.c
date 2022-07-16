#include <common/macro.h>
#include <common/errno.h>
#include <common/asm_ops.h>
#include <common/list.h>
#include <mm/mm.h>
#include <mm/buddy_allocator.h>
#include <virt/ipa_region.h>
#include <virt/stage2_mmu.h>
#include <virt/stage2_mmu_def.h>
#include <virt/vmexit_def.h>
#include <virt/vcpu.h>
#include <virt/sel2.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

struct s2mmu boot_stage2_mmu;

extern void flush_dcache_and_tlb(void);
int unmap_stage2_pt(ptp_t *s2ptp, paddr_t ipn_start, size_t ipn_size);
static int is_ptp_clear(ptp_t *ptp) {
    int i = 0;
    for (i = 0; i < PTP_ENTRIES; i++) {
        pte_t entry = ptp->ent[i];
        if ((entry.pte & ARM64_MMU_PTE_INVALID_MASK) != 0)
            return 0;
    }
    return 1;
}

static int set_pte_flags(pte_t *entry, int level, vm_flags flags) {
    if (entry == NULL) {
        return -EINVAL;
    }
    switch(flags & 0xF) {
        case MMU_ATTR_PAGE_RO:
            if (level == 1) {
                entry->l1_block.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_RO;
                entry->l1_block.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE;
            } else if (level == 2) {
                entry->l2_block.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_RO;
                entry->l2_block.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE;
            } else {
                entry->l3_page.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_RO;
                entry->l3_page.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE;
            }
            break;
        case MMU_ATTR_PAGE_WO:
            if (level == 1) {
                entry->l1_block.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_WO;
                entry->l1_block.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE;
            } else if (level == 2) {
                entry->l2_block.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_WO;
                entry->l2_block.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE;
            } else {
                entry->l3_page.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_WO;
                entry->l3_page.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE;
            }
            break;
        case MMU_ATTR_PAGE_RW:
            if (level == 1) {
                entry->l1_block.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW;
                entry->l1_block.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE;
            } else if (level == 2) {
                entry->l2_block.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW;
                entry->l2_block.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE;
            } else {
                entry->l3_page.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW;
                entry->l3_page.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE;
            }
            break;
        case MMU_ATTR_PAGE_EO:
            if (level == 1) {
                entry->l1_block.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_NONE;
                entry->l1_block.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL;
            } else if (level == 2) {
                entry->l2_block.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_NONE;
                entry->l2_block.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL;
            } else {
                entry->l3_page.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_NONE;
                entry->l3_page.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL;
            }
            break;
        case MMU_ATTR_PAGE_RWE:
            if (level == 1) {
                entry->l1_block.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW;
                entry->l1_block.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL;
            } else if (level == 2) {
                entry->l2_block.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW;
                entry->l2_block.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL;
            } else {
                entry->l3_page.S2AP =
                    ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW;
                entry->l3_page.XN =
                    ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL;
            }
            break;
        default:
            BUG("Unsupported attributes!");
            break;
    }

    /* Set memory attribute */
    int is_device = !!(flags & MMU_ATTR_DEVICE);
    if (level == 1) {
        entry->l1_block.SH = INNER_SHAREABLE;
        entry->l1_block.AF = 1;
        entry->l1_block.mem_attr = is_device ? DEVICE_nGnRE : NORMAL_MEMORY;
    } else if (level == 2) {
        entry->l2_block.SH = INNER_SHAREABLE;
        entry->l2_block.AF = 1;
        entry->l2_block.mem_attr = is_device ? DEVICE_nGnRE : NORMAL_MEMORY;
    } else {
        entry->l3_page.SH = INNER_SHAREABLE;
        entry->l3_page.AF = 1;
        entry->l3_page.mem_attr = is_device ? DEVICE_nGnRE : NORMAL_MEMORY;
    }

    return 0;
}

static int get_next_level_ptp(uint32_t current_level, uint32_t current_index, ptp_t *current_ptp, ptp_t **next_ptp_ret) {
    ptp_t *next_ptp = NULL;
    paddr_t next_ptp_phys = 0;

    if (current_level < 0 || current_level > 2)
        return -EINVAL;
    if (current_index < 0 || current_index >= PTP_ENTRIES)
        return -EINVAL;
    if (current_ptp == NULL || (((uint64_t)current_ptp & PAGE_MASK) != 0))
        return -EINVAL;

    pte_t entry = current_ptp->ent[current_index];
    switch (entry.pte & PTE_DESCRIPTOR_MASK) {
        case PTE_DESCRIPTOR_INVALID:
            next_ptp = bd_alloc(PAGE_SIZE, 12);
            if (next_ptp == NULL) {
                return -ENOMEM; // no enough memory
            }
            memset(next_ptp, 0, PAGE_SIZE);
            next_ptp_phys = virt_to_phys((uint64_t)next_ptp);
            entry.table.is_valid = 1;
            entry.table.is_table = 1;
            entry.table.next_table_addr = next_ptp_phys >> PAGE_SHIFT;
            current_ptp->ent[current_index] = entry;
            *next_ptp_ret = next_ptp;
            return TABLE_TYPE;
        case PTE_DESCRIPTOR_TABLE:
            next_ptp_phys = entry.table.next_table_addr << PAGE_SHIFT;
            next_ptp = (ptp_t *)phys_to_virt(next_ptp_phys);
            *next_ptp_ret = next_ptp;
            return TABLE_TYPE;
        case PTE_DESCRIPTOR_BLOCK:
            /*
             * This condition rarely happens when we map a new page
             */
            next_ptp_phys = entry.table.next_table_addr << PAGE_SHIFT;
            next_ptp = (ptp_t *)phys_to_virt(next_ptp_phys);
            *next_ptp_ret = next_ptp;
            return BLOCK_TYPE;
        default:
            BUG("Unsupported page table type!");
    }
}

static int map_page_invalid(ptp_t *current_ptp, int order, uint32_t level, paddr_t ipa, paddr_t pa, vm_flags flags) {
    uint32_t shift;
    uint32_t index;
    ptp_t *next_level_ptp;
    int ret;

    shift = (3 - level) * PAGE_ORDER + PAGE_SHIFT;
    index = (ipa >> shift) & ((1UL << PAGE_ORDER) - 1);
    pte_t entry = current_ptp->ent[index];

    if (level == 3) {
        if (flags & MMU_NEED_DECRYPT) {
            entry.pte = 0;
            entry.l3_page.pfn = pa >> PAGE_SHIFT;
        } else {
            entry.l3_page.is_valid = 0;
            entry.l3_page.is_page = 1;
            entry.l3_page.pfn = pa >> PAGE_SHIFT;
            set_pte_flags(&entry, 3, flags);
        }
        current_ptp->ent[index] = entry;
        return 0;
    }else{
        if (level != 0 && ((3 - level) * 9 == order)) {
            if (level == 1) {
                entry.l1_block.is_valid = 1;
                entry.l1_block.is_table = 0;
                entry.l1_block.pfn = pa >> (order + PAGE_SHIFT);
            } else {
                entry.l2_block.is_valid = 1;
                entry.l2_block.is_table = 0;
                entry.l2_block.pfn = pa >> (order + PAGE_SHIFT);
            }
            set_pte_flags(&entry, level, flags);
            current_ptp->ent[index] = entry;
            return 0;
        } else {
            int next_page_type =
                get_next_level_ptp(level, index, current_ptp, &next_level_ptp);
            if (next_page_type == TABLE_TYPE) {
                ret = map_page_invalid(next_level_ptp, order, level+1, ipa, pa, flags);
                return ret;
            } else {
                return -ENOMEM;
            }
        }
    }
}
static int map_page(ptp_t *current_ptp, int order, uint32_t level, paddr_t ipa, paddr_t pa, vm_flags flags) {
    uint32_t shift;
    uint32_t index;
    ptp_t *next_level_ptp;
    int ret;

    shift = (3 - level) * PAGE_ORDER + PAGE_SHIFT;
    index = (ipa >> shift) & ((1UL << PAGE_ORDER) - 1);
    pte_t entry = current_ptp->ent[index];

    if (level == 3) {
        if (flags & MMU_NEED_DECRYPT) {
            entry.pte = 0;
            entry.l3_page.pfn = pa >> PAGE_SHIFT;
        } else {
            entry.l3_page.is_valid = 1;
            entry.l3_page.is_page = 1;
            entry.l3_page.pfn = pa >> PAGE_SHIFT;
            set_pte_flags(&entry, 3, flags);
        }
        current_ptp->ent[index] = entry;
        return 0;
    }else{
        if (level != 0 && ((3 - level) * 9 == order)) {
            if (level == 1) {
                entry.l1_block.is_valid = 1;
                entry.l1_block.is_table = 0;
                entry.l1_block.pfn = pa >> (order + PAGE_SHIFT);
            } else {
                entry.l2_block.is_valid = 1;
                entry.l2_block.is_table = 0;
                entry.l2_block.pfn = pa >> (order + PAGE_SHIFT);
            }
            set_pte_flags(&entry, level, flags);
            current_ptp->ent[index] = entry;
            return 0;
        } else {
            int next_page_type =
                get_next_level_ptp(level, index, current_ptp, &next_level_ptp);
            if (next_page_type == TABLE_TYPE) {
                ret = map_page(next_level_ptp, order, level+1, ipa, pa, flags);
                return ret;
            } else {
                return -ENOMEM;
            }
        }
    }
}

static int unmap_range(ptp_t *current_ptp, uint32_t level, paddr_t ipa, size_t size) {
    uint32_t shift;
    uint32_t index;
    uint64_t block_size = 0;
    size_t total_unmapped_size = size;
    size_t current_unmapped_size = 0;
    paddr_t unmapped_ipa = ipa;
    paddr_t next_ptp_phys = 0;
    ptp_t *next_ptp = NULL;
    pte_t entry = {0};

    shift = (3 - level) * PAGE_ORDER + PAGE_SHIFT;
    index = (unmapped_ipa >> shift) & ((1UL << PAGE_ORDER) - 1);

    while (total_unmapped_size > 0) {
        block_size = 1 << shift;
        current_unmapped_size = (block_size < total_unmapped_size) ? block_size : total_unmapped_size;
        entry = current_ptp->ent[index];

        if ((level <= 2) && (entry.pte & PTE_DESCRIPTOR_MASK) == PTE_DESCRIPTOR_TABLE) {
            next_ptp_phys = entry.table.next_table_addr << PAGE_SHIFT;
            next_ptp = (ptp_t *)phys_to_virt(next_ptp_phys);

            unmap_range(next_ptp, level+1, unmapped_ipa, current_unmapped_size);

            if (current_unmapped_size == block_size || is_ptp_clear(next_ptp)) {
                current_ptp->ent[index].pte = PTE_DESCRIPTOR_INVALID;
                bd_free((void *)next_ptp);
            }
        } else {
            current_ptp->ent[index].pte = PTE_DESCRIPTOR_INVALID;
        }

        total_unmapped_size -= current_unmapped_size;
        unmapped_ipa += current_unmapped_size;
    }
    return 0;
}

static int find_page_or_block_pte(struct s2mmu *s2mmu, int start_level, paddr_t ipa, pte_t **pte_out, int *level_out) {
    uint32_t shift = 0;
    uint32_t index = 0;
    int level = start_level;
    ptp_t *current_ptp = NULL;
    ptp_t *next_level_ptp = NULL;
    int next_page_type = 0;

    if ((ipa & PAGE_MASK) != 0 || level_out == NULL) {
        return -EINVAL;
    }
    if (s2mmu == NULL || s2mmu->pgtbl == NULL) {
        return -EINVAL;
    }

    shift = (3 - level) * PAGE_ORDER + PAGE_SHIFT;
    index = (ipa >> shift) & ((1UL << PAGE_ORDER) - 1);
    current_ptp = s2mmu->pgtbl;

    while (level <= 3) {
        pte_t entry = current_ptp->ent[index];
        if ((entry.pte & ARM64_MMU_PTE_INVALID_MASK) == 0)
            return -ENOMAPPING;
        if (level < 3 && ((entry.pte & PTE_DESCRIPTOR_MASK) == PTE_DESCRIPTOR_TABLE)) {
            next_page_type = get_next_level_ptp(level, index, current_ptp, &next_level_ptp);
            if (next_page_type != TABLE_TYPE || next_level_ptp == NULL) {
                BUG("Cannot find next level ptp!");
            }
            current_ptp = next_level_ptp;
            next_level_ptp = NULL;
        } else {
            *level_out = level;
            *pte_out = current_ptp->ent + index;
            return 0;
        }
        level++;
        shift = (3 - level) * PAGE_ORDER + PAGE_SHIFT;
        index = (ipa >> shift) & ((1UL << PAGE_ORDER) - 1);
    }
    return 0;
}

int s2mmu_map_page(struct s2mmu *s2mmu, paddr_t ipa, paddr_t pa, int start_level, vm_flags flags) {
    int ret = 0;
    if ((ipa & PAGE_MASK) != 0 || (pa & PAGE_MASK) != 0) {
        return -EINVAL;
    }
    if (s2mmu == NULL || s2mmu->pgtbl == NULL) {
        return -EINVAL;
    }

    lock(&s2mmu->s2pt_lock);
    ret = map_page(s2mmu->pgtbl, 0, start_level, ipa, pa, flags);
    unlock(&s2mmu->s2pt_lock);
    return ret;
}

int s2mmu_map_page_invalid(struct s2mmu *s2mmu, paddr_t ipa, paddr_t pa, int start_level, vm_flags flags) {
    int ret = 0;
    if ((ipa & PAGE_MASK) != 0 || (pa & PAGE_MASK) != 0) {
        return -EINVAL;
    }
    if (s2mmu == NULL || s2mmu->pgtbl == NULL) {
        return -EINVAL;
    }
   
    lock(&s2mmu->s2pt_lock);
    ret = map_page_invalid(s2mmu->pgtbl, 0, start_level, ipa, pa, flags);
    unlock(&s2mmu->s2pt_lock);

    return ret;
}
int s2mmu_map_range(struct s2mmu *s2mmu, paddr_t ipa, paddr_t pa, int start_level, size_t len, int enable_huge_page, vm_flags flags) {
    size_t total_page_count;
    paddr_t to_mapped_ipa = ipa;
    paddr_t to_mapped_pa = pa;
    int order = 0;

    int ret = 0;

    if (len <= 0) {
        return -EINVAL;
    }
    if (start_level < 0 || start_level > 3) {
        return -EINVAL;
    }
    if ((ipa & PAGE_MASK) != 0 || (pa & PAGE_MASK) != 0) {
        return -EINVAL;
    }
    if (s2mmu == NULL || s2mmu->pgtbl == NULL) {
        return -EINVAL;
    }

    total_page_count = len / PAGE_SIZE + (((len % PAGE_SIZE) > 0) ? 1 : 0);

    while(total_page_count) {
        if (enable_huge_page == 1) {
            if ((total_page_count >= (1 << 18)) && !(to_mapped_ipa & ((1 << 18) - 1)) && !(to_mapped_pa & ((1 << 18) - 1))) {
                order = 18;
            } else if ((total_page_count >= (1 << 9)) && !(to_mapped_ipa & ((1 << 9) - 1)) && !(to_mapped_pa & ((1 << 9) - 1))) {
                order = 9;
            } else {
                order = 0;
            }
        } else {
            order = 0; // Do not use huge page
        }
       
        ret = map_page(s2mmu->pgtbl, order, start_level, to_mapped_ipa, to_mapped_pa, flags);
        if (ret != 0) { // ERROR
            return ret;
        }

        total_page_count -= (1 << order);
        to_mapped_pa += (1 << (order + PAGE_SHIFT));
        to_mapped_ipa += (1 << (order + PAGE_SHIFT));
    }

    return 0; // success
}

int s2mmu_unmap_range(struct s2mmu *s2mmu, paddr_t ipa, size_t len) {
    if ((ipa & PAGE_MASK) != 0 || (len <= 0)) {
        return -EINVAL;
    }
    if (s2mmu == NULL || s2mmu->pgtbl == NULL) {
        return -EINVAL;
    }

    return unmap_stage2_pt(s2mmu->pgtbl, ipa >> PAGE_SHIFT, len >> PAGE_SHIFT);
}

int s2mmu_unmap_page(struct s2mmu *s2mmu, paddr_t ipa) {
    if ((ipa & PAGE_MASK) != 0) {
        return -EINVAL;
    }
    if (s2mmu == NULL || s2mmu->pgtbl == NULL) {
        return -EINVAL;
    }

    return unmap_range(s2mmu->pgtbl, 1, ipa, PAGE_SIZE); //The initial lookup level in FVP is 1
}

int s2mmu_protect(struct s2mmu *s2mmu, paddr_t ipa, size_t len, vm_flags flags) {
    pte_t *entry = 0;
    int level = 0;
    int order = 0;
    size_t left_len = len;
    size_t tmp_len = 0;
    paddr_t next_ipa = ipa;

    if ((ipa & PAGE_MASK) != 0 || len < 0) {
        return -EINVAL;
    }
    if (s2mmu == NULL || s2mmu->pgtbl == NULL) {
        return -EINVAL;
    }

    while(left_len > 0) {
        if (find_page_or_block_pte(s2mmu, 1, next_ipa, &entry, &level) == 0)
            set_pte_flags(entry, level, flags);
        else
            return -ENOMAPPING;

        order = (3 - level) * PAGE_ORDER;
        tmp_len = (1 << (order + PAGE_SHIFT));
        left_len -= tmp_len;
        next_ipa += tmp_len;
    }

    return 0;
}

/*
 * Translate a ipa to pa, and get its flags
 */
int s2mmu_query(struct s2mmu *s2mmu, paddr_t ipa, paddr_t *pa, int *level_out, vm_flags *flags) {
    pte_t *entry = 0;
    int level = 0;

    if ((ipa & PAGE_MASK) != 0 || pa == NULL || flags == NULL || level_out == NULL) {
        return -EINVAL;
    }
    if (s2mmu == NULL || s2mmu->pgtbl == NULL) {
        return -EINVAL;
    }

    if (find_page_or_block_pte(s2mmu, 1, ipa, &entry, &level) == 0) {
        switch (level) {
            case 1:
                *pa = entry->l1_block.pfn << (18 + PAGE_SHIFT);
                if (entry->l1_block.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_RO && entry->l1_block.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE) {
                    *flags = MMU_ATTR_PAGE_RO;
                } else if (entry->l1_block.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_WO && entry->l1_block.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE) {
                    *flags = MMU_ATTR_PAGE_WO;
                } else if (entry->l1_block.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW && entry->l1_block.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE) {
                    *flags = MMU_ATTR_PAGE_RW;
                } else if (entry->l1_block.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_NONE && entry->l1_block.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL) {
                    *flags = MMU_ATTR_PAGE_EO;
                } else if (entry->l1_block.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW && entry->l1_block.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL) {
                    *flags = MMU_ATTR_PAGE_RWE;
                }
                break;
            case 2:
                *pa = entry->l2_block.pfn << (9 + PAGE_SHIFT);
                if (entry->l2_block.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_RO && entry->l2_block.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE) {
                    *flags = MMU_ATTR_PAGE_RO;
                } else if (entry->l2_block.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_WO && entry->l2_block.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE) {
                    *flags = MMU_ATTR_PAGE_WO;
                } else if (entry->l2_block.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW && entry->l2_block.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE) {
                    *flags = MMU_ATTR_PAGE_RW;
                } else if (entry->l2_block.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_NONE && entry->l2_block.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL) {
                    *flags = MMU_ATTR_PAGE_EO;
                } else if (entry->l2_block.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW && entry->l2_block.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL) {
                    *flags = MMU_ATTR_PAGE_RWE;
                }
                break;
            case 3:
                *pa = entry->l3_page.pfn << PAGE_SHIFT;
                if (entry->l3_page.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_RO && entry->l3_page.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE) {
                    *flags = MMU_ATTR_PAGE_RO;
                } else if (entry->l3_page.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_WO && entry->l3_page.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE) {
                    *flags = MMU_ATTR_PAGE_WO;
                } else if (entry->l3_page.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW && entry->l3_page.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE) {
                    *flags = MMU_ATTR_PAGE_RW;
                } else if (entry->l3_page.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_NONE && entry->l3_page.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL) {
                    *flags = MMU_ATTR_PAGE_EO;
                } else if (entry->l3_page.S2AP == ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW && entry->l3_page.XN == ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL) {
                    *flags = MMU_ATTR_PAGE_RWE;
                }
                break;
            default:
                BUG("Invalid page table level!");
                break;
        }
        *level_out = level;
        return 0;
    } else {
        return -ENOMAPPING;
    }
    return 0;
}

/*
 * Create an empty s2mmu struct
 */
struct s2mmu *create_stage2_mmu(void) {
    struct s2mmu *new_s2mmu = bd_alloc(sizeof(*new_s2mmu), 0);
    memset(new_s2mmu, 0, sizeof(struct s2mmu));

    list_init(&(new_s2mmu->ipa_region_list));
    void *pgtbl = bd_alloc(PAGE_SIZE, 13); // We must align the level 1 page table to 13 bits.
    memset(pgtbl, 0, PAGE_SIZE);
    new_s2mmu->pgtbl = pgtbl;

    lock_init(&new_s2mmu->s2pt_lock);
    return new_s2mmu;
}

void install_stage2_pt(struct s2mmu *s2mmu) {
    if (s2mmu != NULL && s2mmu->pgtbl != NULL) {
        ptp_t *to_install_pgtbl = s2mmu->pgtbl;

        write_vsttbr((paddr_t)to_install_pgtbl);
        flush_dcache_and_tlb();
    }
}


#define MEM_BASE        0x06400000UL
#define MEM_END         0x08000000UL
inline static void check_ptp_addr(paddr_t ipa) {
    if (ipa < MEM_BASE || ipa >= MEM_END) {
        printf("error ptp addr out of bound, ipa is 0x%lx\n", ipa);
    }
}


inline static void check_pte_table(uint64_t pte) {
    if ((pte & PTE_DESCRIPTOR_MASK) != PTE_DESCRIPTOR_TABLE) {
        printf("pte is not a table, pte is 0x%llx\n", pte);
    }
}
#define PTE_NUM 512
#define DIV_UPPER_SHIFT(start, shift) ((start +  (1 << shift) - 1) >> shift)
/*
 * Translate a stage-2 page table from IPN to HPN
 * Return: target pte_t, { .pte = 0 } for not found
 * FIXME: only support 3-level stage-2 PT with 4K granule
 * [ipn_start, ipn_end)
 */
int unmap_stage2_pt(ptp_t *s2ptp, paddr_t ipn_start, size_t ipn_size) {
    paddr_t ipn_end = ipn_start + ipn_size;
    uint32_t l1_shift = (3 - 1) * PAGE_ORDER;
    uint32_t l1_index_start = (ipn_start >> l1_shift) & ((1UL << PAGE_ORDER) - 1);
    uint32_t l1_index_end = DIV_UPPER_SHIFT(ipn_end, l1_shift) & ((1UL << PAGE_ORDER) - 1);

    uint32_t l2_shift = (3 - 2) * PAGE_ORDER;
    uint32_t l2_index_start = (ipn_start >> l2_shift) & ((1UL << PAGE_ORDER) - 1);
    uint32_t l2_index_end = DIV_UPPER_SHIFT(ipn_end, l2_shift) & ((1UL << PAGE_ORDER) - 1);
   
    uint32_t l3_shift = (3 - 3) * PAGE_ORDER;
    uint32_t l3_index_start = (ipn_start >> l3_shift) & ((1UL << PAGE_ORDER) - 1);
    uint32_t l3_index_end = DIV_UPPER_SHIFT(ipn_end, l3_shift) & ((1UL << PAGE_ORDER) - 1);

    // l1
    ptp_t* l1_table = s2ptp;
    check_ptp_addr((paddr_t)l1_table);
    for (int l1_index = l1_index_start; l1_index < l1_index_end; l1_index++) {
        pte_t l1_entry = l1_table->ent[l1_index];
        if ((l1_entry.pte & ARM64_MMU_PTE_INVALID_MASK) == 0) {
            continue;
        } else {
            // l2
            check_pte_table(l1_entry.pte);
            ptp_t* l2_table = (ptp_t *)((uint64_t)l1_entry.table.next_table_addr << PAGE_SHIFT);
            check_ptp_addr((paddr_t)l2_table);
            int l2_index_start_tmp = (l1_index == l1_index_start) ? l2_index_start: 0;
            int l2_index_end_tmp = (l1_index == l1_index_end) ? l2_index_end: PTE_NUM;
            for (int l2_index = l2_index_start_tmp; l2_index < l2_index_end_tmp; l2_index++) {
                pte_t l2_entry = l2_table->ent[l2_index];   
                if ((l2_entry.pte & ARM64_MMU_PTE_INVALID_MASK) == 0) {
                    continue;
                } else {
                    // l3
                    check_pte_table(l2_entry.pte);
                    ptp_t* l3_table = (ptp_t *)((uint64_t)l2_entry.table.next_table_addr << PAGE_SHIFT);
                    check_ptp_addr((paddr_t)l3_table);
                    int l3_index_start_tmp = (l2_index == l2_index_start) ? l3_index_start: 0;
                    int l3_index_end_tmp = (l2_index == l2_index_end) ? l3_index_end: PTE_NUM;
                    for (int l3_index = l3_index_start_tmp; l3_index < l3_index_end_tmp; l3_index++) {
                        l3_table->ent[l3_index].pte = 0;
                    }
                    if ((l3_index_start_tmp == 0 && l3_index_end_tmp == PTE_NUM) ||
                           is_ptp_clear(l3_table) ) {
                        // free page table page, then clear upper page table entry
                        bd_free((void *)l3_table);
                        l2_table->ent[l2_index].pte = 0;
                    }
                }
            }
            if ((l2_index_start_tmp == 0 && l2_index_end_tmp == PTE_NUM) ||
                   is_ptp_clear(l2_table) ) {
                // free page table page, then clear upper page table entry
                bd_free((void *) l2_table);
                l1_table->ent[l1_index].pte = 0;
            }
        }
    }
    return 0;
}

/*
 * Translate a stage-2 page table from IPN to HPN
 * Return: target pte_t, { .pte = 0 } for not found
 * FIXME: only support 3-level stage-2 PT with 4K granule
 */
pte_t translate_stage2_pt(ptp_t *s2ptp, paddr_t ipn) {
    pte_t ret = { .pte = 0 };
    ptp_t *l2_table = NULL;
    pte_t l1_entry;
    uint32_t l1_shift = (3 - 1) * PAGE_ORDER;
    uint32_t l1_index = (ipn >> l1_shift) & ((1UL << PAGE_ORDER) - 1);
   
    if (!s2ptp) return ret;
    l1_entry = s2ptp->ent[l1_index];
    if ((l1_entry.pte & ARM64_MMU_PTE_INVALID_MASK) == 0 ||
            (l1_entry.pte & PTE_DESCRIPTOR_MASK) != PTE_DESCRIPTOR_TABLE) {
        return ret;
    }
    l2_table = (ptp_t *)((uint64_t)l1_entry.table.next_table_addr << PAGE_SHIFT);

    ptp_t *l3_table = NULL;
    pte_t l2_entry;
    uint32_t l2_shift = (3 - 2) * PAGE_ORDER;
    uint32_t l2_index = (ipn >> l2_shift) & ((1UL << PAGE_ORDER) - 1);
   
    if (!l2_table) return ret;
    l2_entry = l2_table->ent[l2_index];
    if ((l2_entry.pte & ARM64_MMU_PTE_INVALID_MASK) == 0 ||
            (l2_entry.pte & PTE_DESCRIPTOR_MASK) != PTE_DESCRIPTOR_TABLE) {
        return ret;
    }
    l3_table = (ptp_t *)((uint64_t)l2_entry.table.next_table_addr << PAGE_SHIFT);
   
    uint32_t l3_shift = (3 - 3) * PAGE_ORDER;
    uint32_t l3_index = (ipn >> l3_shift) & ((1UL << PAGE_ORDER) - 1);

    if (!l3_table) return ret;
    return l3_table->ent[l3_index];
}


pte_t s2mmu_translate_page(struct s2mmu *s2mmu, ptp_t *s2ptp, paddr_t ipn) {
    pte_t pte_ret;
    lock(&s2mmu->s2pt_lock);
    pte_ret = translate_stage2_pt(s2ptp, ipn);
    unlock(&s2mmu->s2pt_lock);
    return pte_ret;
}
