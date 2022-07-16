cmake_minimum_required (VERSION 3.5)

add_library(${PROJECT_NAME}-virt OBJECT
    sel2.c
    stage2_mmu.c
    virt_helpers.S
    vm.c
    kvm_relay.c
    vm_cache.c
    vm_handler.c
)
