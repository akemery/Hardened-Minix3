#ifndef MACHINE_CHECK_CONST_H
#define MACHINE_CHECK_CONST_H


/*
 * cpuid_supported
 */
#define   MSR    (1 << 5) // Model Specific Registers
#define   MCE    (1 << 7) // Machine Check Exception
#define   MCA    (1 << 14) // Machine Check Architecture

/** IA32_MCG_CAP FLAGS*/

//Count field, bits 7:0
#define MCG_CTL_P 	(1 << 8) // control MSR present
#define MCG_EXT_P 	(1 << 9) // extended MSRs present
#define MCG_CMCI_P 	(1<< 10) // Corrected MC error counting/signaling extension present
#define MCG_TES_P 	(1 << 11) // threshold-based error status present
//#define MCG_EXT_CNT, bits 23:16
#define MCG_SER_P 	(1 << 24) // software error recovery support present
#define MCG_EMC_P 	(1 << 25) // Enhanced Machine Check Capability
#define MCG_ELOG_P 	(1 << 26) // extended error logging
#define MCG_LMCE_P 	(1 << 27) // local machine check exception

/* */
#define IA32_FEATURE_CONTROL 	0x3A
#define IA32_FEATURE_CONTROL_LOCK 	(1 << 0)
#define IA32_FEATURE_CONTROL_LMCE 	(1 << 20)


/* Global Control MSRs */
#define IA32_MCG_CAP 		0x179
#define IA32_MCG_STATUS 		0x17A
#define IA32_MCG_CTL 	  	0x17B
#define MSR_IA32_MCG_EXT_CTL 	0x4D0

/* */
#define IA32_MC0_CTL	0x400
#define IA32_MC0_STATUS	0x401
#define IA32_MC0_ADDR	0x402
#define IA32_MC0_MISC	0x403


#define IA32_MCx_CTL(x)	(IA32_MC0_CTL + 4*(x))
#define IA32_MCx_STATUS(x)	(IA32_MC0_STATUS + 4*(x))
#define IA32_MCx_ADDR(x)	(IA32_MC0_ADDR + 4*(x))
#define IA32_MCx_MISC(x)	(IA32_MC0_MISC + 4*(x))

//#define IA32_MCx_CTL_Val	0xffffffff


#define MCi_PCC_REGISTER_VALID (1 << 25) // for 64bit= 57 , high on 32bit = 57 - 32 = 26
#define MCi_ADDR_REGISTER_VALID (1 << 26) //high
#define MCi_MISCV_REGISTER_VALID (1 << 27) //high
#define MCi_REGISTER_VALID (1 << 31) //high 63-32
#define MCi_STATUT_UC (1 << 29) //high
#define MCi_STATUT_S (1 << 24) //high
#define MCi_STATUT_AR (1 << 28) //high
#define MCi_STATUT_EN (1 << 29) //high


#define MCIP (1<<2)
#define RIPV (1<<0)


/* Set MCE bit 6 on CR4'*/
#define CR4_MCE	(1L<<6)


#endif /* MACHINE_CHECK_CONST_H */
