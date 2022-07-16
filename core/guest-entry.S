#include <common/asm.h>
#include <common/def.h>
#include <virt/registers-asm.h>
#include <virt/asm-offsets.h>
#include <virt/vmexit_def.h>

el1_sync:
        save_guest_states x0, x1, x2
        mov x0, #S_VISOR_VMEXIT_SYNC
        bl exit_guest 

el1_irq:
        mov x0, #S_VISOR_VMEXIT_IRQ
        b .

el1_fiq:
        save_guest_states x0, x1, x2
        mov x0, #S_VISOR_VMEXIT_FIQ
        bl exit_guest 

el1_error:
        mov x0, #S_VISOR_VMEXIT_ERR
        b .

el2h_sync:
        mov x0, #S_VISOR_HYP_SYNC
        b . 
    
el2h_irq:
        mov x0, #S_VISOR_HYP_IRQ
        b .

el2h_fiq:
        mov x0, #S_VISOR_HYP_FIQ
        b .

el2h_error:
        mov x0, #S_VISOR_HYP_ERR
        b .

.macro invalid_vector	label, target = hyp_panic
	.align	2
\label:
	b \target
ENDPROC(\label)
.endm

	/* None of these should ever happen */
	invalid_vector	el2t_sync_invalid
	invalid_vector	el2t_irq_invalid
	invalid_vector	el2t_fiq_invalid
	invalid_vector	el2t_error_invalid

	.ltorg

	.align 11

.macro valid_vect target
	.align 7
	b	\target
.endm

.macro invalid_vect target
	.align 7
	b	\target
.endm

ENTRY(s_visor_hyp_vector)
	invalid_vect	el2t_sync_invalid	// Synchronous EL2t
	invalid_vect	el2t_irq_invalid	// IRQ EL2t
	invalid_vect	el2t_fiq_invalid	// FIQ EL2t
	invalid_vect	el2t_error_invalid	// Error EL2t

	valid_vect	el2h_sync		// Synchronous EL2h
	valid_vect	el2h_irq                // IRQ EL2h
	valid_vect	el2h_fiq 	        // FIQ EL2h
	valid_vect	el2h_error		// Error EL2h

	valid_vect	el1_sync		// Synchronous 64-bit EL1
	valid_vect	el1_irq			// IRQ 64-bit EL1
	valid_vect	el1_fiq	        	// FIQ 64-bit EL1
	valid_vect	el1_error		// Error 64-bit EL1

	valid_vect	el1_sync		// Synchronous 32-bit EL1
	valid_vect	el1_irq			// IRQ 32-bit EL1
	valid_vect	el1_fiq	        	// FIQ 32-bit EL1
	valid_vect	el1_error		// Error 32-bit EL1
ENDPROC(s_visor_hyp_vector)


ENTRY(enter_guest)
    /* We call nested functions, follow the ABI. */
    stp         x29, x30, [sp, #-16]!

    stp         x0, x1, [sp, #-16]!
    get_host_gp_regs x0
    save_all_gp_regs x0 // except x0 and x1
    ldp         x2, x3, [sp], #16 //read x0 and x1
    stp         x2, x3, [x0, #CPU_XREG_OFFSET(0)]
    restore_guest_states x0, x1
    tlbi    vmalls12e1
    dsb     sy
    isb

    eret
ENDPROC(enter_guest)

ENTRY(exit_guest)
    get_host_gp_regs x1
    restore_all_gp_regs x1

    ldp          x29, x30, [sp], #16
    ret
ENDPROC(exit_guest)
