#pragma once
#include <common/list.h>
#include <common/lock.h>
#include <stdint.h>
#include <stddef.h>

/**
 * Outer cacheability for TBBR1:
 * NC: non-cacheable
 * WBWA: write-back read-allocate write-allocate cacheable
 * WTnWA: write-back read-allocate no write-allocate cacheable
 * WBnWA: write-back read-allocate no write-allocate cacheable
 **/
#define TCR_ORGN1_NC     (0x0 << 26)
#define TCR_ORGN1_WBWA   (0x1 << 26)
#define TCR_ORGN1_WTnWA  (0x2 << 26)
#define TCR_ORGN1_WBnWA  (0x3 << 26)
/* Inner shareability for TBBR1 */
#define TCR_IRGN1_NC     (0x0 << 24)
#define TCR_IRGN1_WBWA   (0x1 << 24)
#define TCR_IRGN1_WTnWA  (0x2 << 24)
#define TCR_IRGN1_WBnWA  (0x3 << 24)
/* Outer shareability for TBBR0 */
#define TCR_ORGN0_NC     (0x0 << 10)
#define TCR_ORGN0_WBWA   (0x1 << 10)
#define TCR_ORGN0_WTnWA  (0x2 << 10)
#define TCR_ORGN0_WBnWA  (0x3 << 10)
/* Inner shareability for TBBR0 */
#define TCR_IRGN0_NC     (0x0 << 8)
#define TCR_IRGN0_WBWA   (0x1 << 8)
#define TCR_IRGN0_WTnWA  (0x2 << 8)
#define TCR_IRGN0_WBnWA  (0x3 << 8)

#define INNER_SHAREABLE  (0x3)
#define NORMAL_MEMORY    (0xF) // Outer/Inner Write-Back Cacheable
#define DEVICE_nGnRE     (0x1)

/**
 * Whether a translation table walk is performed on a TLB miss, for an
 * address that is translated using TTBR1_EL1/TTBR0_EL1.
 **/
#define TCR_EPD1_WALK   (0x0 << 23)
#define TCR_EPD1_FAULT  (0x1 << 23)
#define TCR_EPD0_WALK   (0x0 << 7)
#define TCR_EPD0_FAULT  (0x1 << 7)

/* Who defines the ASID */
#define TCR_A1_TTBR0  (0x0 << 22)
#define TCR_A1_TTBR1  (0x1 << 22)

/* TCR_EL1 */

/**
 * Four-level page table for 4KB pages
 *  - p0d_t is the address of the 4K page
 *  - each p1d_t contains 512 p1e_t that points to one p0d_t
 *  - each p2d_t contains 512 p2e_t that points to one p1d_t
 *  - each p3d_t contains 512 p3e_t that points to one p2d_t
 *  - each p4d_t contains 512 p4e_t that points to one p3d_t
 *
 * Relations to the ARM document terminalogies:
 * p1d_t: level 3 table
 * P2d_t: level 2 table
 * p3d_t: level 1 table
 * p4d_t: level 0 table
 **/

/* Table attributes */
#define ARM64_MMU_ATTR_TBL_AP_TABLE_NOEFFECT      (0)
#define ARM64_MMU_ATTR_TBL_AP_TABLE_NOEL0         (1)
#define ARM64_MMU_ATTR_TBL_AP_TABLE_NOWRITE       (2)
#define ARM64_MMU_ATTR_TBL_AP_TABLE_NOACCESS      (3)

/* Block/Page access permission */
#define ARM64_MMU_ATTR_STAGE2_PAGE_AP_NONE        (0)
#define ARM64_MMU_ATTR_STAGE2_PAGE_AP_RO          (1)
#define ARM64_MMU_ATTR_STAGE2_PAGE_AP_WO          (2)
#define ARM64_MMU_ATTR_STAGE2_PAGE_AP_RW          (3)

/* Block/Page execution permission */
#define ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_ALL       (0)
#define ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_EL0       (1)
#define ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_NONE      (2)
#define ARM64_MMU_ATTR_STAGE2_PAGE_XN_X_EL1       (3)

#define ARM64_MMU_ATTR_PAGE_AF_NONE               (0)
#define ARM64_MMU_ATTR_PAGE_AF_ACCESSED           (1)

#define ARM64_MMU_PTE_INVALID_MASK                (1 << 0)
#define ARM64_MMU_PTE_TABLE_MASK                  (1 << 1)

#define IS_PTE_INVALID(pte) (!((pte) & ARM64_MMU_PTE_INVALID_MASK))
#define IS_PTE_TABLE(pte) (!!((pte) & ARM64_MMU_PTE_TABLE_MASK))

#define MMU_ATTR_PAGE_RO                          1
#define MMU_ATTR_PAGE_WO                          2
#define MMU_ATTR_PAGE_RW                          3  
#define MMU_ATTR_PAGE_EO                          4  
#define MMU_ATTR_PAGE_RWE                         5  

#define MMU_ATTR_DEVICE                           0x10
/* Need to decrypt the data before mapping in VSTTBR */
#define MMU_NEED_DECRYPT                          0x20

#define PAGE_SHIFT                                (12)
#ifndef PAGE_SIZE
#define PAGE_SIZE                                 (1 << (PAGE_SHIFT))
#endif
#define PAGE_MASK                                 (PAGE_SIZE - 1)
#define PAGE_ORDER                                (9)

#define PTP_ENTRIES  (1 << PAGE_ORDER)
#define L3  (3)
#define L2  (2)
#define L1  (1)
#define L0  (0)

#define PTP_INDEX_MASK      ((1 << (PAGE_ORDER)) - 1)
#define L0_INDEX_SHIFT      ((3 * PAGE_ORDER) + PAGE_SHIFT)
#define L1_INDEX_SHIFT      ((2 * PAGE_ORDER) + PAGE_SHIFT)
#define L2_INDEX_SHIFT      ((1 * PAGE_ORDER) + PAGE_SHIFT)
#define L3_INDEX_SHIFT      ((0 * PAGE_ORDER) + PAGE_SHIFT)

#define GET_L0_INDEX(addr) ((addr >> L0_INDEX_SHIFT) & PTP_INDEX_MASK)
#define GET_L1_INDEX(addr) ((addr >> L1_INDEX_SHIFT) & PTP_INDEX_MASK)
#define GET_L2_INDEX(addr) ((addr >> L2_INDEX_SHIFT) & PTP_INDEX_MASK)
#define GET_L3_INDEX(addr) ((addr >> L3_INDEX_SHIFT) & PTP_INDEX_MASK)

#define PGTBL_4K_BITS                             (9)
#define PGTBL_4K_ENTRIES                          (1 << (PGTBL_4K_BITS))
#define PGTBL_4K_MAX_INDEX                        ((PGTBL_4K_ENTRIES) - 1)

#define ARM64_MMU_L1_BLOCK_ORDER                  (18)
#define ARM64_MMU_L2_BLOCK_ORDER                  (9)
#define ARM64_MMU_L3_PAGE_ORDER                   (0)

#define ARM64_MMU_L0_BLOCK_PAGES  (PTP_ENTRIES * ARM64_MMU_L1_BLOCK_PAGES)
#define ARM64_MMU_L1_BLOCK_PAGES  (1UL << ARM64_MMU_L1_BLOCK_ORDER)
#define ARM64_MMU_L2_BLOCK_PAGES  (1UL << ARM64_MMU_L2_BLOCK_ORDER)
#define ARM64_MMU_L3_PAGE_PAGES   (1UL << ARM64_MMU_L3_PAGE_ORDER)

#define L0_PER_ENTRY_PAGES  (ARM64_MMU_L0_BLOCK_PAGES)
#define L1_PER_ENTRY_PAGES  (ARM64_MMU_L1_BLOCK_PAGES)
#define L2_PER_ENTRY_PAGES        (ARM64_MMU_L2_BLOCK_PAGES)
#define L3_PER_ENTRY_PAGES  (ARM64_MMU_L3_PAGE_PAGES)

#define ARM64_MMU_L1_BLOCK_SIZE   (ARM64_MMU_L1_BLOCK_PAGES << PAGE_SHIFT)
#define ARM64_MMU_L2_BLOCK_SIZE   (ARM64_MMU_L2_BLOCK_PAGES << PAGE_SHIFT)
#define ARM64_MMU_L3_PAGE_SIZE    (ARM64_MMU_L3_PAGE_PAGES << PAGE_SHIFT)

#define ARM64_MMU_L1_BLOCK_MASK   (ARM64_MMU_L1_BLOCK_SIZE - 1)
#define ARM64_MMU_L2_BLOCK_MASK   (ARM64_MMU_L2_BLOCK_SIZE - 1)
#define ARM64_MMU_L3_PAGE_MASK    (ARM64_MMU_L3_PAGE_SIZE - 1)

#define GET_VA_OFFSET_L1(va)      (va & ARM64_MMU_L1_BLOCK_MASK)
#define GET_VA_OFFSET_L2(va)      (va & ARM64_MMU_L2_BLOCK_MASK)
#define GET_VA_OFFSET_L3(va)      (va & ARM64_MMU_L3_PAGE_MASK)

#define PTE_DESCRIPTOR_INVALID                    (0)
#define PTE_DESCRIPTOR_BLOCK                      (1)
#define PTE_DESCRIPTOR_TABLE                      (3)
#define PTE_DESCRIPTOR_MASK                       (3)

/* PAGE TABLE PAGE TYPE */
#define TABLE_TYPE              1
#define BLOCK_TYPE              2

typedef uint32_t vm_flags;

/* table format */
typedef union {
    struct {
        uint64_t is_valid        : 1,
            is_table        : 1,
            ignored1        : 10,
            next_table_addr : 36,
            reserved1       : 4,
            ignored2        : 7,
            reserved2       : 5;
    } table;
    struct {
        uint64_t is_valid        : 1,
            is_table        : 1,
            mem_attr        : 4,   // Memory attributes index
            S2AP            : 2,   // Data access permissions
            SH              : 2,   // Shareability
            AF              : 1,   // Accesss flag
            zero            : 1,  
            reserved1       : 4,
            nT              : 1,
            reserved2       : 13,
            pfn             : 18,
            reserved3       : 3,
            DBM             : 1,   // Dirty bit modifier
            Contiguous      : 1,
            XN              : 2, 
            soft_reserved   : 4,
            PBHA            : 4,   // Page based hardware attributes
            reserved4       : 1;
    } l1_block;
    struct {
        uint64_t is_valid        : 1,
            is_table        : 1,
            mem_attr        : 4,   // Memory attributes index
            S2AP            : 2,   // Data access permissions
            SH              : 2,   // Shareability
            AF              : 1,   // Accesss flag
            zero            : 1,  
            reserved1       : 4,
            nT              : 1,
            reserved2       : 4,
            pfn             : 27,
            reserved3       : 3,
            DBM             : 1,   // Dirty bit modifier
            Contiguous      : 1,
            XN              : 2,   // Execute never
            soft_reserved   : 4,
            PBHA            : 4,   // Page based hardware attributes
            reserved4       : 1;
    } l2_block;
    struct {
        uint64_t is_valid        : 1,
            is_page         : 1,
            mem_attr        : 4,   // Memory attributes index
            S2AP            : 2,   // Data access permissions
            SH              : 2,   // Shareability
            AF              : 1,   // Accesss flag
            zero            : 1,  
            pfn             : 36,
            reserved        : 3,
            DBM             : 1,   // Dirty bit modifier
            Contiguous      : 1,
            XN              : 2,   // Execute never
            soft_reserved   : 4,
            PBHA            : 4,   // Page based hardware attributes
            reserved2       : 1;
    } l3_page;
    uint64_t pte;
} pte_t;

/* page_table_page type */
typedef struct {
    pte_t ent[1 << PGTBL_4K_BITS];
} ptp_t;

struct s2mmu {
    struct list_head ipa_region_list;
    ptp_t *pgtbl;
    struct lock s2pt_lock;
};

extern struct s2mmu boot_stage2_mmu;
struct s2mmu *create_stage2_mmu(void);
int s2mmu_map_page(struct s2mmu *s2mmu, paddr_t ipa, paddr_t pa, int start_level, vm_flags flags);
int s2mmu_map_page_invalid(struct s2mmu *s2mmu, paddr_t ipa, paddr_t pa, int start_level, vm_flags flags);
pte_t s2mmu_translate_page(struct s2mmu *s2mmu, ptp_t *s2ptp, paddr_t ipn);
int s2mmu_map_range(struct s2mmu *s2mmu, paddr_t ipa, paddr_t pa, int start_level, size_t len, int enable_huge_page, vm_flags flags);
int s2mmu_unmap_range(struct s2mmu *s2mmu, paddr_t ipa, size_t len);
int s2mmu_unmap_page(struct s2mmu *s2mmu, paddr_t ipa);
int s2mmu_protect(struct s2mmu *s2mmu, paddr_t ipa, size_t len, vm_flags flags);
int s2mmu_query(struct s2mmu *s2mmu, paddr_t ipa, paddr_t *pa, int *level_out, vm_flags *flags);
void install_stage2_pt(struct s2mmu *s2mmu);

pte_t translate_stage2_pt(ptp_t *s2ptp, paddr_t ipn);

static inline void write_vstcr(uint32_t vstcr_value)
{
    asm volatile ("msr vstcr_el2, %0" : : "r" (vstcr_value));
}

static inline uint32_t read_vstcr(void)
{
    uint32_t vstcr_value = 0;
    asm volatile ("mrs %0, vstcr_el2":"=r" (vstcr_value));
    return vstcr_value;
}

static inline void write_vtcr(uint32_t vtcr_value)
{
    asm volatile ("msr vtcr_el2, %0" : : "r" (vtcr_value));
}

static inline uint32_t read_vtcr(void)
{
    uint32_t vtcr_value = 0;
    asm volatile ("mrs %0, vtcr_el2":"=r" (vtcr_value));
    return vtcr_value;
}

static inline void write_vttbr(paddr_t vttbr_value)
{
    asm volatile ("msr vttbr_el2, %0" : : "r" (vttbr_value));
}

static inline paddr_t read_vttbr(void)
{
    paddr_t vttbr_value = 0;
    asm volatile ("mrs %0, vttbr_el2":"=r" (vttbr_value));
    return vttbr_value;
}

static inline void write_vsttbr(paddr_t vsttbr_value)
{
    asm volatile ("msr vsttbr_el2, %0" : : "r" (vsttbr_value));
}

static inline paddr_t read_vsttbr(void)
{
    paddr_t vsttbr_value = 0;
    asm volatile ("mrs %0, vsttbr_el2":"=r" (vsttbr_value));
    return vsttbr_value;
}
