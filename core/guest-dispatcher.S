#include <common/asm.h>
#include <virt/registers-asm.h>
#include <virt/asm-offsets.h>
#include <common/def.h>

LOCAL_S_VISOR_ENTRY(vector_std_smc_entry)
	b	.	/* SMC should not be hereOA */
S_VISOR_ENTRY_END(vector_std_smc_entry)

LOCAL_S_VISOR_ENTRY(vector_fast_smc_entry)
	b	.	/* SMC should not be here */
S_VISOR_ENTRY_END(vector_fast_smc_entry)

LOCAL_S_VISOR_ENTRY(vector_kvm_trap_smc_entry)
        bl      __get_core_pos
        ldr     x1, =current_cpu_stack_sps
        mov     w2, #8
        umaddl  x1, w0, w2, x1  // x1 = x1 + w0 * w2
        ldr     x1, [x1]
        mov     sp, x1

        bl forward_smc_to_vm
        cbnz     x0, 1f
	smc	#1              // sync
        b       .               //not return
        1:
        smc	#2              // irq
        b	.	/* SMC should not return */
S_VISOR_ENTRY_END(vector_kvm_trap_smc_entry)

LOCAL_S_VISOR_ENTRY(vector_kvm_shared_memory_register_entry)
    bl 	    	kvm_shared_memory_register
    smc	    	#0x10
    b	.	/* SMC should not return */
S_VISOR_ENTRY_END(vector_kvm_shared_memory_register_entry)

LOCAL_S_VISOR_ENTRY(vector_kvm_shared_memory_handle_entry)
    bl 	    	kvm_shared_memory_handle
    smc	    	#0x10
    b	.	/* SMC should not return */
S_VISOR_ENTRY_END(vector_kvm_shared_memory_handle_entry)

LOCAL_S_VISOR_ENTRY(vector_cpu_on_entry)
        bl          __get_core_pos
        ldr         x1, =current_cpu_stack_sps
        mov         w2, #8
        umaddl      x1, w0, w2, x1  // x0 = x1 + w0 * w2
        ldr         x1, [x1]
        mov         sp, x1

        bl          secondary_core_entrypoint

        /* Hardcode the same arguments with OPTEE */
        ldr         x0, =0xbe000001
        ldr         x1, =0x0
        ldr         x2, =0xf2440000
        ldr         x3, =0x8000000100
        ldr         x4, =0x1
        ldr         x5, =00
        ldr         x6, =0xe051820
        ldr         x7, =0xfffffffe

        smc         #0
        b  .        /* SMC should not return */
S_VISOR_ENTRY_END(vector_cpu_on_entry)

LOCAL_S_VISOR_ENTRY(vector_cpu_off_entry)
        smc #0
        b  . 	/* SMC should not return */
S_VISOR_ENTRY_END(vector_cpu_off_entry)

LOCAL_S_VISOR_ENTRY(vector_cpu_resume_entry)
        smc #0
        b  . 	/* SMC should not return */
S_VISOR_ENTRY_END(vector_cpu_resume_entry)

LOCAL_S_VISOR_ENTRY(vector_cpu_suspend_entry)
        smc #0
        b  . 	/* SMC should not return */
S_VISOR_ENTRY_END(vector_cpu_suspend_entry)

LOCAL_S_VISOR_ENTRY(vector_fiq_entry)
        smc #0
        b  . 	/* SMC should not return */
S_VISOR_ENTRY_END(vector_fiq_entry)

LOCAL_S_VISOR_ENTRY(vector_system_off_entry)
        smc #0
        b  . 	/* SMC should not return */
S_VISOR_ENTRY_END(vector_system_off_entry)

LOCAL_S_VISOR_ENTRY(vector_system_reset_entry)
        smc #0
        b  . 	/* SMC should not return */
S_VISOR_ENTRY_END(vector_system_reset_entry)

S_VISOR_ENTRY(s_visor_handler_table)
	b	vector_std_smc_entry
	b	vector_fast_smc_entry
        b       vector_kvm_trap_smc_entry
        b       vector_kvm_shared_memory_register_entry
        b       vector_kvm_shared_memory_handle_entry
        b       vector_cpu_on_entry
        b       vector_cpu_off_entry
        b       vector_cpu_resume_entry
        b       vector_cpu_suspend_entry
	b	vector_fiq_entry
        b       vector_system_off_entry
        b       vector_system_reset_entry
S_VISOR_ENTRY_END(s_visor_handler_table)
