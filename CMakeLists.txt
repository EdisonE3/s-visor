cmake_minimum_required (VERSION 3.5)

set(CMAKE_VERBOSE_MAKEFILE on)

set(ROOTDIR "${CMAKE_SOURCE_DIR}")

set(CROSS_COMPILE "${ROOTDIR}/../toolchains/aarch64/bin/aarch64-linux-gnu-")

set(CMAKE_C_COMPILER "${CROSS_COMPILE}gcc")
set(CMAKE_CPP_COMPILER "${CROSS_COMPILE}cpp")
set(CMAKE_ASM_COMPILER "${CROSS_COMPILE}gcc")
set(CMAKE_OBJ_COPY "${CROSS_COMPILE}objcopy")

set(CMAKE_C_FLAGS "-std=gnu99 -fdiagnostics-show-option -Wall -Werror-implicit-function-declaration -nostdinc -nostdlib -march=armv8.4-a -mgeneral-regs-only -nostartfiles -g" CACHE STRING "" FORCE)

SET(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS} -D__ASSEMBLY__" CACHE STRING "" FORCE)

set(CMAKE_GEN_ASM_FLAGS "-std=gnu99 -fdiagnostics-show-option -Wall -Werror-implicit-function-declaration -nostdinc -nostdlib -march=armv8.4-a -nostartfiles -S" CACHE STRING "" FORCE)

project (S-visor C ASM)

set(S_VISOR_INCLUDE_PATH       "${CMAKE_SOURCE_DIR}/include")
set(S_VISOR_CORE_PATH          "${CMAKE_SOURCE_DIR}/core")
set(S_VISOR_LIB_PATH           "${CMAKE_SOURCE_DIR}/lib")
set(S_VISOR_MM_PATH            "${CMAKE_SOURCE_DIR}/mm")
set(S_VISOR_PLAT_PATH          "${CMAKE_SOURCE_DIR}/plat")
set(S_VISOR_DRIVER_PATH        "${CMAKE_SOURCE_DIR}/drivers")
set(S_VISOR_VIRT_PATH          "${CMAKE_SOURCE_DIR}/virt")
set(S_VISOR_COMMON_PATH          "${CMAKE_SOURCE_DIR}/common")


include_directories("${S_VISOR_INCLUDE_PATH}")
include_directories("${S_VISOR_INCLUDE_PATH}/arch/aarch64")
include_directories("${S_VISOR_INCLUDE_PATH}/plat/arm/common")
include_directories("${S_VISOR_INCLUDE_PATH}/plat/arm/board/common")
include_directories("${CMAKE_SOURCE_DIR}/plat/arm/board/fvp/include")
include_directories("${S_VISOR_INCLUDE_PATH}/plat/common")
include_directories("${S_VISOR_INCLUDE_PATH}/lib/libc")
include_directories("${S_VISOR_INCLUDE_PATH}/lib/libc/aarch64")
include_directories("${S_VISOR_INCLUDE_PATH}/plat/arm/common/aarch64")
include_directories("${S_VISOR_INCLUDE_PATH}/lib/el3_runtime/aarch64")
include_directories("${S_VISOR_INCLUDE_PATH}/services")

add_subdirectory("${S_VISOR_CORE_PATH}")
add_subdirectory("${S_VISOR_LIB_PATH}")
add_subdirectory("${S_VISOR_MM_PATH}")
add_subdirectory("${S_VISOR_PLAT_PATH}")
add_subdirectory("${S_VISOR_DRIVER_PATH}")
add_subdirectory("${S_VISOR_VIRT_PATH}")
add_subdirectory("${S_VISOR_COMMON_PATH}")

set(LINK_SCRIPT "linker.lds")
set(GENERATED_HEADER "asm-offsets.h")

add_executable(s_visor.img 
    $<TARGET_OBJECTS:${PROJECT_NAME}-core>
    $<TARGET_OBJECTS:${PROJECT_NAME}-lib>
    $<TARGET_OBJECTS:${PROJECT_NAME}-mm>
    $<TARGET_OBJECTS:${PROJECT_NAME}-plat>
    $<TARGET_OBJECTS:${PROJECT_NAME}-driver>
    $<TARGET_OBJECTS:${PROJECT_NAME}-virt>
    $<TARGET_OBJECTS:${PROJECT_NAME}-common>
)

target_include_directories(
    s_visor.img
    PRIVATE
        "${S_VISOR_INCLUDE_PATH}"
)

set_property(
    TARGET s_visor.img
    APPEND_STRING
    PROPERTY
        LINK_FLAGS
        "-T ${CMAKE_CURRENT_BINARY_DIR}/${LINK_SCRIPT} -e primary_core_entrypoint"
)

set_property(
    TARGET s_visor.img
    APPEND_STRING
    PROPERTY
        DEPENDS
        "${LINK_SCRIPT}"
)

add_custom_target(
    header_generation
    COMMAND ${CMAKE_C_COMPILER}
    -I${CMAKE_SOURCE_DIR}/plat/arm/board/fvp/include
    -I${CMAKE_SOURCE_DIR}/include/plat/arm/common
    -I${CMAKE_SOURCE_DIR}/include/arch/aarch64
    -I${CMAKE_SOURCE_DIR}/include/
    -I${CMAKE_SOURCE_DIR}/include/plat/arm/board/common/
    -S ${CMAKE_SOURCE_DIR}/virt/asm-offsets.c -o ${CMAKE_SOURCE_DIR}/include/virt/asm-offsets.s
    #COMMAND sed -f ${CMAKE_SOURCE_DIR}/scripts/asm-offsets.sed <
    #${CMAKE_SOURCE_DIR}/include/virt/asm-offsets.s >
    #${CMAKE_SOURCE_DIR}/include/virt/asm-offsets.h
    COMMAND sh ${CMAKE_SOURCE_DIR}/scripts/gen_asm_headers.sh
    # COMMAND rm ${CMAKE_SOURCE_DIR}/include/virt/asm-offsets.s
)

add_dependencies(s_visor.img header_generation)

add_custom_command(
    TARGET s_visor.img
    PRE_LINK
    COMMAND ${CMAKE_CPP_COMPILER} -D__ASSEMBLY__ -P -C 
    -I${CMAKE_SOURCE_DIR}/plat/arm/board/fvp/include
    -I${CMAKE_SOURCE_DIR}/include/plat/arm/common
    -I${CMAKE_SOURCE_DIR}/include/arch/aarch64
    -I${CMAKE_SOURCE_DIR}/include/
    -I${CMAKE_SOURCE_DIR}/include/plat/arm/board/common/
    ${CMAKE_SOURCE_DIR}/core/linker.ld.S -o ${LINK_SCRIPT}
)

add_custom_command(
    TARGET s_visor.img
    POST_BUILD
    COMMAND ${CMAKE_OBJ_COPY} -O binary -S s_visor.img s_visor.bin
)
