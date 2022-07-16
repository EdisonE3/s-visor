#pragma once

#define S_VISOR_MAX_SIZE_PER_CORE (2048 + 64)

enum {
    REQ_KVM_TO_S_VISOR_FLUSH_IPA = 0,
    REQ_KVM_TO_S_VISOR_UNMAP_IPA,
    REQ_KVM_TO_S_VISOR_REMAP_IPA,
    REQ_KVM_TO_S_VISOR_BOOT,
    REQ_KVM_TO_S_VISOR_SHUTDOWN,
    REQ_KVM_TO_S_VISOR_GENERAL,
    REQ_KVM_TO_S_VISOR_MEMCPY,
    REQ_KVM_TO_S_VISOR_UPDATE_TOP
};

/* NOTE: KVM_SMC_UNMAP_IPA uses variable length of shared memory */
typedef struct {
    uint32_t sec_vm_id;
    uint32_t vcpu_id;
    uint32_t req_type;
    union {
        /* No extra info for GENERAL */;
        struct {
            uint64_t qemu_s1ptp;
            uint64_t nr_vcpu;
        } boot;
        struct {
            /* [start_pfn, start_pfn + nr_pages). Current granularity is 8M */
            uint64_t src_start_pfn;
            uint64_t dst_start_pfn;
            uint64_t nr_pages;
            /* ipn_list[0] -> src_start_pfn, ipn_list[1] -> src_start_pfn + 1 */
            uint64_t ipn_list[2048];
        } remap_ipa;
        struct {
            /* Tuples [start_pfn, end_pfn]. Maybe need a bitmap to batch? */
            uint64_t ipn_ranges[0];
        } unmap_ipa;
        struct {
            /* [start_pfn, start_pfn + nr_pages). Current granularity is 8M */
            uint64_t src_start_pfn;
            uint64_t dst_start_pfn;
            uint64_t nr_pages;
        } memcpy;
        uint64_t top_pfn;
        /* No extra info for SHUTDOWN */;
    };
} kvm_smc_req_t;

#define S_VISOR_MAX_SUPPORTED_PHYSICAL_CORE_NUM 4

void *get_s_visor_shared_buf(void);

void *get_gp_reg_region(unsigned int core_id);

kvm_smc_req_t *get_smc_req_region(unsigned int core_id);
