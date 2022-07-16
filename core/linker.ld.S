

#include <platform_def.h>

OUTPUT_FORMAT(PLATFORM_LINKER_FORMAT)
OUTPUT_ARCH(aarch64)
ENTRY(primary_core_entrypoint)

MEMORY {
    ROM (rx): ORIGIN = S_VISOR_RO_BASE, LENGTH = S_VISOR_RO_LIMIT - S_VISOR_RO_BASE
    RAM (rwx): ORIGIN = S_VISOR_RW_BASE, LENGTH = S_VISOR_RW_LIMIT - S_VISOR_RW_BASE
}

SECTIONS {
    . = S_VISOR_RO_BASE;
    ASSERT(. == ALIGN(PAGE_SIZE),
           "GOBIIDAE_LOAD_BASE address is not aligned on a page boundary.")

    __GOBIIDAE_LOAD_START__ = .;

    .text . : {
        __TEXT_START__ = .;
        *core_entrypoint.s.o(.text*)
        *(.text*)
        *(.vectors)
        . = ALIGN(PAGE_SIZE);
        __TEXT_END__ = .;
    } >ROM

    .rodata . : {
        __RODATA_START__ = .;
        *(.rodata*)

        /* Ensure 8-byte alignment for descriptors and ensure inclusion */
        . = ALIGN(8);

        . = ALIGN(PAGE_SIZE);
        __RODATA_END__ = .;
    } >ROM

    /*
     * Define a linker symbol to mark start of the RW memory area for this
     * image.
     */
    
    __RW_START__ = S_VISOR_RW_BASE ;
    . = S_VISOR_RW_BASE;

    /*
     * .data must be placed at a lower address than the stacks if the stack
     * protector is enabled. Alternatively, the .data.stack_protector_canary
     * section can be placed independently of the main .data section.
     */
   .data . : {
        __DATA_START__ = .;
        *(.data*)
        __DATA_END__ = .;
    } >RAM

    /*
     * .rela.dyn needs to come after .data for the read-elf utility to parse
     * this section correctly. Ensure 8-byte alignment so that the fields of
     * RELA data structure are aligned.
     */
    . = ALIGN(8);
    __RELA_START__ = .;
    __RELA_END__ = .;

    stacks (NOLOAD) : {
        __STACKS_START__ = .;
        *(tzfw_normal_stacks)
        __STACKS_END__ = .;
    } >RAM

    /*
     * The .bss section gets initialised to 0 at runtime.
     * Its base address should be 16-byte aligned for better performance of the
     * zero-initialization code.
     */
    .bss (NOLOAD) : ALIGN(16) {
        __BSS_START__ = .;
        *(.bss*)
        *(COMMON)
        __BSS_END__ = .;
    } >RAM
    /*
     * Define a linker symbol to mark end of the RW memory area for this
     * image.
     */
    __RW_END__ = .;
    __GOBIIDAE_LOAD_END__ = .;

    ASSERT(. <= S_VISOR_RW_LIMIT, "GOBIIDAE_LOAD image has exceeded its limit.")
}
