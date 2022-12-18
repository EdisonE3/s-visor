#pragma once

#define S_VISOR_MAX_SIZE_PER_CORE (2048 + 64)
#define REALM_SUCCESS			0U
#define REALM_ERROR			1U

enum {
    // old S-Visor APIs
    REQ_KVM_TO_S_VISOR_FLUSH_IPA = 0,
    REQ_KVM_TO_S_VISOR_UNMAP_IPA,
    REQ_KVM_TO_S_VISOR_REMAP_IPA,
    REQ_KVM_TO_S_VISOR_BOOT,
    REQ_KVM_TO_S_VISOR_SHUTDOWN,
    REQ_KVM_TO_S_VISOR_GENERAL,
    REQ_KVM_TO_S_VISOR_MEMCPY,
    REQ_KVM_TO_S_VISOR_UPDATE_TOP,
    REQ_KVM_TO_RMM_HANDLER
};

enum {
    // rmi between kvm and rmm
	SMC_RMM_VERSION = 99,
    SMC_RMM_FEATURES,
    SMC_RMM_GRANULE_DELEGATE,
    SMC_RMM_GRANULE_UNDELEGATE,
    SMC_RMM_REALM_CREATE,
    SMC_RMM_REALM_DESTROY,
    SMC_RMM_REALM_ACTIVATE,
    SMC_RMM_REC_CREATE,
    SMC_RMM_REC_DESTROY,
    SMC_RMM_REC_ENTER,
    SMC_RMM_DATA_CREATE,
    SMC_RMM_DATA_CREATE_UNKNOWN,
    SMC_RMM_DATA_DESTROY,
    SMC_RMM_RTT_CREATE,
	SMC_RMM_RTT_DESTROY,
    SMC_RMM_RTT_FOLD,
    SMC_RMM_RTT_MAP_UNPROTECTED,
    SMC_RMM_RTT_UNMAP_UNPROTECTED,
    SMC_RMM_RTT_READ_ENTRY,
    SMC_RMM_PSCI_COMPLETE,
    SMC_RMM_REC_AUX_COUNT,
    SMC_RMM_RTT_INIT_RIPAS,
    SMC_RMM_RTT_SET_RIPAS
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
