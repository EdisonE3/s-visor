#include <asm_macros.S>

    .local	platform_normal_stacks
	.weak	plat_set_my_stack
	.weak	plat_get_my_stack
	.weak	platform_set_stack
	.weak	platform_get_stack

#define PLATFORM_STACK_SIZE             UL(0x1000)

#define CACHE_WRITEBACK_GRANULE		64

    /* -----------------------------------------------------
	 * uintptr_t plat_get_my_stack ()
	 *
	 * For cold-boot BL images, only the primary CPU needs a
	 * stack. This function returns the stack pointer for a
	 * stack allocated in device memory.
	 * -----------------------------------------------------
	 */
func plat_get_my_stack
	get_up_stack platform_normal_stacks, PLATFORM_STACK_SIZE
	ret
endfunc plat_get_my_stack

	/* -----------------------------------------------------
	 * void plat_set_my_stack ()
	 *
	 * For cold-boot BL images, only the primary CPU needs a
	 * stack. This function sets the stack pointer to a stack
	 * allocated in normal memory.
	 * -----------------------------------------------------
	 */
func plat_set_my_stack
	get_up_stack platform_normal_stacks, PLATFORM_STACK_SIZE
	mov sp, x0
	ret
endfunc plat_set_my_stack

	/* -----------------------------------------------------
	 * Single cpu stack in normal memory.
	 * Used for C code during boot, PLATFORM_STACK_SIZE bytes
	 * are allocated
	 * -----------------------------------------------------
	 */
declare_stack platform_normal_stacks, .data, \
		PLATFORM_STACK_SIZE, 1, CACHE_WRITEBACK_GRANULE
