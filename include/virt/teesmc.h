#pragma once

#define TEESMC_VM_RV(func_num) \
		((SMC_TYPE_FAST << FUNCID_TYPE_SHIFT) | \
		 ((SMC_32) << FUNCID_CC_SHIFT) | \
		 (62 << FUNCID_OEN_SHIFT) | \
		 ((func_num) & FUNCID_NUM_MASK))

/*
 * Issued when returning from initial entry.
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_ENTRY_DONE
 * r1/x1	Pointer to entry vector
 */
#define TEESMC_VM_FUNCID_RETURN_ENTRY_DONE		0
#define TEESMC_VM_RETURN_ENTRY_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_ENTRY_DONE)


/*
 * Issued when returning from "cpu_on" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_ON_DONE
 * r1/x1	0 on success and anything else to indicate error condition
 */
#define TEESMC_VM_FUNCID_RETURN_ON_DONE		1
#define TEESMC_VM_RETURN_ON_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_ON_DONE)

/*
 * Issued when returning from "cpu_off" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_OFF_DONE
 * r1/x1	0 on success and anything else to indicate error condition
 */
#define TEESMC_VM_FUNCID_RETURN_OFF_DONE		2
#define TEESMC_VM_RETURN_OFF_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_OFF_DONE)

/*
 * Issued when returning from "cpu_suspend" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_SUSPEND_DONE
 * r1/x1	0 on success and anything else to indicate error condition
 */
#define TEESMC_VM_FUNCID_RETURN_SUSPEND_DONE	3
#define TEESMC_VM_RETURN_SUSPEND_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_SUSPEND_DONE)

/*
 * Issued when returning from "cpu_resume" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_RESUME_DONE
 * r1/x1	0 on success and anything else to indicate error condition
 */
#define TEESMC_VM_FUNCID_RETURN_RESUME_DONE		4
#define TEESMC_VM_RETURN_RESUME_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_RESUME_DONE)

/*
 * Issued when returning from "std_smc" or "fast_smc" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_CALL_DONE
 * r1-4/x1-4	Return value 0-3 which will passed to normal world in
 *		r0-3/x0-3
 */
#define TEESMC_VM_FUNCID_RETURN_CALL_DONE		5
#define TEESMC_VM_RETURN_CALL_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_CALL_DONE)

/*
 * Issued when returning from "fiq" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_FIQ_DONE
 */
#define TEESMC_VM_FUNCID_RETURN_FIQ_DONE		6
#define TEESMC_VM_RETURN_FIQ_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_FIQ_DONE)

/*
 * Issued when returning from "system_off" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_SYSTEM_OFF_DONE
 */
#define TEESMC_VM_FUNCID_RETURN_SYSTEM_OFF_DONE	7
#define TEESMC_VM_RETURN_SYSTEM_OFF_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_SYSTEM_OFF_DONE)

/*
 * Issued when returning from "system_reset" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_SYSTEM_RESET_DONE
 */
#define TEESMC_VM_FUNCID_RETURN_SYSTEM_RESET_DONE	8
#define TEESMC_VM_RETURN_SYSTEM_RESET_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_SYSTEM_RESET_DONE)

#define TEESMC_VM_FUNCID_RETURN_ENTRY_DONE		0
#define TEESMC_VM_RETURN_ENTRY_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_ENTRY_DONE)



/*
 * Issued when returning from "cpu_on" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_ON_DONE
 * r1/x1	0 on success and anything else to indicate error condition
 */
#define TEESMC_VM_FUNCID_RETURN_ON_DONE		1
#define TEESMC_VM_RETURN_ON_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_ON_DONE)

/*
 * Issued when returning from "cpu_off" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_OFF_DONE
 * r1/x1	0 on success and anything else to indicate error condition
 */
#define TEESMC_VM_FUNCID_RETURN_OFF_DONE		2
#define TEESMC_VM_RETURN_OFF_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_OFF_DONE)

/*
 * Issued when returning from "cpu_suspend" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_SUSPEND_DONE
 * r1/x1	0 on success and anything else to indicate error condition
 */
#define TEESMC_VM_FUNCID_RETURN_SUSPEND_DONE	3
#define TEESMC_VM_RETURN_SUSPEND_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_SUSPEND_DONE)

/*
 * Issued when returning from "cpu_resume" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_RESUME_DONE
 * r1/x1	0 on success and anything else to indicate error condition
 */
#define TEESMC_VM_FUNCID_RETURN_RESUME_DONE		4
#define TEESMC_VM_RETURN_RESUME_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_RESUME_DONE)

/*
 * Issued when returning from "std_smc" or "fast_smc" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_CALL_DONE
 * r1-4/x1-4	Return value 0-3 which will passed to normal world in
 *		r0-3/x0-3
 */
#define TEESMC_VM_FUNCID_RETURN_CALL_DONE		5
#define TEESMC_VM_RETURN_CALL_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_CALL_DONE)

/*
 * Issued when returning from "fiq" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_FIQ_DONE
 */
#define TEESMC_VM_FUNCID_RETURN_FIQ_DONE		6
#define TEESMC_VM_RETURN_FIQ_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_FIQ_DONE)

/*
 * Issued when returning from "system_off" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_SYSTEM_OFF_DONE
 */
#define TEESMC_VM_FUNCID_RETURN_SYSTEM_OFF_DONE	7
#define TEESMC_VM_RETURN_SYSTEM_OFF_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_SYSTEM_OFF_DONE)

/*
 * Issued when returning from "system_reset" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_VM_RETURN_SYSTEM_RESET_DONE
 */
#define TEESMC_VM_FUNCID_RETURN_SYSTEM_RESET_DONE	8
#define TEESMC_VM_RETURN_SYSTEM_RESET_DONE \
	TEESMC_VM_RV(TEESMC_VM_FUNCID_RETURN_SYSTEM_RESET_DONE)

/*========================The following is defines for TSP===================*/

/*
 * SMC function IDs that TSP uses to signal various forms of completions
 * to the secure payload dispatcher.
 */
#define TSP_ENTRY_DONE		0xf2000000
#define TSP_ON_DONE		0xf2000001
#define TSP_OFF_DONE		0xf2000002
#define TSP_SUSPEND_DONE	0xf2000003
#define TSP_RESUME_DONE		0xf2000004
#define TSP_PREEMPTED		0xf2000005
#define TSP_ABORT_DONE		0xf2000007
#define TSP_SYSTEM_OFF_DONE	0xf2000008
#define TSP_SYSTEM_RESET_DONE	0xf2000009

/*
 * Function identifiers to handle S-EL1 interrupt through the synchronous
 * handling model. If the TSP was previously interrupted then control has to
 * be returned to the TSPD after handling the interrupt else execution can
 * remain in the TSP.
 */
#define TSP_HANDLED_S_EL1_INTR		0xf2000006

/* SMC function ID that TSP uses to request service from secure monitor */
#define TSP_GET_ARGS		0xf2001000

/*
 * Identifiers for various TSP services. Corresponding function IDs (whether
 * fast or yielding) are generated by macros defined below
 */
#define TSP_ADD		0x2000
#define TSP_SUB		0x2001
#define TSP_MUL		0x2002
#define TSP_DIV		0x2003
#define TSP_HANDLE_SEL1_INTR_AND_RETURN	0x2004

/*
 * Identify a TSP service from function ID filtering the last 16 bits from the
 * SMC function ID
 */
#define TSP_BARE_FID(fid)	((fid) & 0xffff)

/*
 * Generate function IDs for TSP services to be used in SMC calls, by
 * appropriately setting bit 31 to differentiate yielding and fast SMC calls
 */
#define TSP_YIELD_FID(fid)	((TSP_BARE_FID(fid) | 0x72000000))
#define TSP_FAST_FID(fid)	((TSP_BARE_FID(fid) | 0x72000000) | (1u << 31))

/* SMC function ID to request a previously preempted yielding smc */
#define TSP_FID_RESUME		TSP_YIELD_FID(0x3000)
/*
 * SMC function ID to request abortion of a previously preempted yielding SMC. A
 * fast SMC is used so that the TSP abort handler does not have to be
 * reentrant.
 */
#define TSP_FID_ABORT		TSP_FAST_FID(0x3001)

/*
 * Total number of function IDs implemented for services offered to NS clients.
 * The function IDs are defined above
 */
#define TSP_NUM_FID		0x5

/* TSP implementation version numbers */
#define TSP_VERSION_MAJOR	0x0 /* Major version */
#define TSP_VERSION_MINOR	0x1 /* Minor version */

/*
 * Standard Trusted OS Function IDs that fall under Trusted OS call range
 * according to SMC calling convention
 */
#define TOS_CALL_COUNT		0xbf00ff00 /* Number of calls implemented */
#define TOS_UID			0xbf00ff01 /* Implementation UID */
/*				0xbf00ff02 is reserved */
#define TOS_CALL_VERSION	0xbf00ff03 /* Trusted OS Call Version */

