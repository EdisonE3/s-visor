cmake_minimum_required (VERSION 3.5)

add_library(${PROJECT_NAME}-mm OBJECT
    mm.c
    mmops.c
    memcpy.S
    mmu_helpers.S
    buddy_allocator.c
    shadow_alloc.c
    tzc400.c
    stage1_mmu.c
    tlsf.c
)
