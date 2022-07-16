//#include <virt/vcpu.h>
#include <common/asm.h>
#include <virt/asm-offsets.h>
#include <virt/teesmc.h>

.globl	primary_core_entrypoint
.globl	secondary_core_entrypoint
.globl  el2_early_stack

.section .data.el2_early_stack ; .align 16
	el2_early_stack: .long 0x1000

.section .text.core_entrypoint, "ax"

.globl global_s_visor_states

.type primary_core_entrypoint, @function
.func primary_core_entrypoint

primary_core_entrypoint:
    mov x20, x0
    mov x21, x1
    mov x22, x2
    mov x23, x3
    
    msr spsel, #1
    ldr x0, =el2_early_stack
    ldr x1, =0x1000
    add x0, x0, x1
    mov sp, x0
    
    mov x0, x21
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    bl	ti_early_platform_setup2
    
    // install global s_visor to per-cpu struct
    ldr x1, =global_s_visor_states
    mov x0, #0 // primary core id is 0
    mov w2, #GLOBAL_S_VISOR_STATE_SIZE
    umaddl x0, w0, w2, x1 // x0 = x1 + w0 * w2
    msr tpidr_el2, x0
    
    // install fault handlers
    ldr x0, =s_visor_hyp_vector
    msr vbar_el2,x0
    
    bl  init_primary_core

    ldr x0, =0xbe000000
    adr x1, s_visor_handler_table
    smc #0
hang:
    b hang

.endfunc
    .size primary_core_entrypoint, .-primary_core_entrypoint

.type secondary_core_entrypoint, @function
.func secondary_core_entrypoint

secondary_core_entrypoint:
    stp	 x29, x30, [sp, #-16]!
    mov	 x29, sp

    mov x0, x21
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr

    // install global s_visor to per-cpu struct
    bl __get_core_pos // x0 = core_id 
    ldr x1, =global_s_visor_states
    mov w2, #GLOBAL_S_VISOR_STATE_SIZE
    umaddl x0, w0, w2, x1  // x0 = x1 + w0 * w2
    msr tpidr_el2, x0

    // install fault handlers
    ldr x0, =s_visor_hyp_vector
    msr vbar_el2,x0

    bl init_secondary_core

    ldp	 x29, x30, [sp], #16
    ret

.endfunc
    .size secondary_core_entrypoint, .-secondary_core_entrypoint
