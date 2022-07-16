cmake_minimum_required (VERSION 3.5)

add_library(${PROJECT_NAME}-plat OBJECT
    arm/common/s_visor_setup.c
    arm/common/arm_console.c
    arm/common/aarch64/arm_helpers.S
    arm/board/fvp/aarch64/fvp_helpers.S
    common/aarch64/platform_helpers.S
    common/aarch64/plat_common.c
    arm/board/fvp/include/plat_macros.S
)
