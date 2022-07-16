#include <common/asm.h>
#include <arch.h>

/* uint64_t __get_core_pos(void); */
BEGIN_FUNC(__get_core_pos)
	mrs	x0, mpidr_el1
	/*
	 * Shift MPIDR value if it's not already shifted.
	 * Using logical shift ensures AFF0 to be filled with zeroes.
	 * This part is necessary even if CFG_CORE_THREAD_SHIFT is 0 because
	 * MT bit can be set on single threaded systems where all the AFF0
	 * values are zeroes.
	 */
	tst	x0, #MPIDR_MT_MASK // x0 & (1 << 24)
	lsl	x3, x0, #MPIDR_AFFINITY_BITS //x3 = x0 << 8
	csel	x3, x3, x0, eq

	/*
	 * At this point the MPIDR layout is always shifted so it looks
	 * as follows AFF2 -> cluster, AFF1 -> core, AFF0 -> thread
	 */
	/* Calculate CorePos = (ClusterId * (cores/cluster)) + CoreId */
	ubfx	x0, x3, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x1, x3, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS
	add	x0, x0, x1, LSL #2
	ret
END_FUNC(__get_core_pos)
