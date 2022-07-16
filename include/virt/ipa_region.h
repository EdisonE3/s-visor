#pragma once
#include <common/list.h>
#include <virt/stage2_mmu.h>
#include <stdint.h>

enum ir_type {
    IR_EAGER_MAPPING = 0,
    IR_LAZY_MAPPING,
};

struct ipa_region {
    struct list_head region_node;

    paddr_t ipa_start;
    paddr_t pa_start;   // corresponding pa for this ipa, *0* means any pa is OK
    size_t size;
    uint32_t region_attr; // MMU ATTR for this region
    uint32_t region_type; //EAGER Mapping or LAZY Mapping?
};

int add_ipa_region(struct s2mmu *s2mmu, struct ipa_region *region);
int delete_ipa_region(struct s2mmu *s2mmu, struct ipa_region *region);
struct ipa_region *find_ipa_region_by_ipa(struct s2mmu *s2mmu, paddr_t ipa);
int sync_ipa_regions_to_page_table(struct s2mmu *s2mmu);
