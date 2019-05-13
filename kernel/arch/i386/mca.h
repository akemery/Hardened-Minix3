#ifndef MCA_H
#define MCA_H

#define ALL_1s 0xFFFFFFFF

#define USE_MCA 0

#define get_n_banks(n) (n)&(0xFF) 

/* Global Control MSRs */
#define IA32_MCG_CAP 		0x179
#define IA32_MCG_STATUS 	0x17A
#define IA32_MCG_CTL 	  	0x17B

/** IA32_MCG_CAP bits**/
#define MCG_CTL_P 	(1 << 8)
#define MCG_EXT_P 	(1 << 9) // extended MSRs present
#define MCG_CMCI_P 	(1<< 10) // Corrected MC error counting/signaling extension present
#define MCG_TES_P 	(1 << 11) // threshold-based error status present
#define MCG_SER_P 	(1 << 24) // software error recovery support present
#define MCG_EMC_P 	(1 << 25) // Enhanced Machine Check Capability
#define MCG_ELOG_P 	(1 << 26) // extended error logging

/** Error reporting bank 0**/
#define IA32_MC0_CTL	0x400
#define IA32_MC0_STATUS	0x401
#define IA32_MC0_ADDR	0x402
#define IA32_MC0_MISC	0x403

/* Set MCE bit 6 on CR4'*/
#define CR4_MCE	       (1 << 6)

#define MCG_LMCE_P 	(1 << 27) // local machine check exception

#define RIPV   (1 << 0)
#define EIPV   (1 << 1)
#define MCIP   (1 << 2)

#endif /* MCA_H */
