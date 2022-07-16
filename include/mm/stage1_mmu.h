#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <common/errno.h>

#define PAGE_SHIFT                                (12)
#ifndef PAGE_SIZE
#define PAGE_SIZE                                 (1 << (PAGE_SHIFT))
#endif
#define PAGE_MASK                                 (PAGE_SIZE - 1)
#define PAGE_ORDER                                (9)

#define PGTBL_4K_BITS                             (9)
#define PGTBL_4K_ENTRIES                          (1 << (PGTBL_4K_BITS))
#define PGTBL_4K_MAX_INDEX                        ((PGTBL_4K_ENTRIES) - 1)

#define ARM64_MMU_PTE_INVALID_MASK                (1 << 0)
#define ARM64_MMU_PTE_TABLE_MASK                  (1 << 1)

#define IS_PTE_INVALID(pte) (!((pte) & ARM64_MMU_PTE_INVALID_MASK))
#define IS_PTE_TABLE(pte) (!!((pte) & ARM64_MMU_PTE_TABLE_MASK))

/* table format */
typedef union {
    struct {
        uint64_t is_valid        : 1,
            is_table        : 1,
            ignored1        : 10,
            next_table_addr : 36,
            reserved1       : 4,
            ignored2        : 7,
            PXN             : 1,
            UXN              : 1,
            AP              : 2,
            NS              : 1;
    } table;
    struct {
        uint64_t is_valid        : 1,
            is_table        : 1,
            AttrIndx        : 3,
            NS              : 1,
            AP              : 2,
            SH              : 2,
            AF              : 1,
            nG              : 1,
            OA              : 4,
            nT              : 1,
            reserved2       : 13,
            pfn             : 18,
            reserved3       : 3,
            DBM             : 1,
            Contiguous      : 1,
            PXN             : 1,
            UXN              : 1,
            soft_reserved   : 4,
            PBHA            : 4,   // Page based hardware attributes
            ignored         : 1;
    } l1_block;
    struct {
        uint64_t is_valid        : 1,
            is_table        : 1,
            AttrIndx        : 3,
            NS              : 1,
            AP              : 2,
            SH              : 2,
            AF              : 1,
            nG              : 1,
            OA              : 4,
            nT              : 1,
            reserved2       : 4,
            pfn             : 27,
            reserved3       : 3,
            DBM             : 1,
            Contiguous      : 1,
            PXN             : 1,
            UXN              : 1,
            soft_reserved   : 4,
            PBHA            : 4,   // Page based hardware attributes
            ignored         : 1;
    } l2_block;
    struct {
        uint64_t is_valid        : 1,
            is_page         : 1,
            AttrIndx        : 3,
            NS              : 1,
            AP              : 2,
            SH              : 2,
            AF              : 1,
            nG              : 1,
            pfn             : 36,
            reserved        : 3,
            DBM             : 1,
            Contiguous      : 1,
            PXN             : 1,
            UXN              : 1,
            soft_reserved   : 4,
            PBHA            : 4,   // Page based hardware attributes
            ignored         : 1;
    } l3_page;
    uint64_t pte;
} s1_pte_t;

/* page_table_page type */
typedef struct {
    s1_pte_t ent[1 << PGTBL_4K_BITS];
} s1_ptp_t;

int map_vfn_to_pfn(s1_ptp_t *s1ptp, vaddr_t vfn, paddr_t pfn);
int map_vfn(s1_ptp_t *s1ptp, vaddr_t vfn, s1_pte_t *shadow_ptep);
int unmap_vfn(s1_ptp_t *s1ptp, vaddr_t vfn, s1_pte_t *shadow_ptep);
