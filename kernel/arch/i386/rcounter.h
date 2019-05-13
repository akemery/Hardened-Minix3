#ifndef RCOUNTER_H
#define RCOUNTER_H

#include <minix/const.h>
#include <sys/cdefs.h>

#ifndef __ASSEMBLY__

#include <minix/com.h>
#include <minix/portio.h>

#define INS_2_EXEC 0x7270E00

#define USE_INS_COUNTER        1
#define INS_THRESHOLD 0xFFFFFFFF

#define INTEL_MSR_PERFMON_CRT1         0xc2
#define INTEL_MSR_PERFMON_CRT2         0xc3
#define INTEL_MSR_PERFMON_SEL1        0x187
#define INTEL_MSR_PERFMON_SEL2        0x188
#define INTEL_MSR_FIXED_CTR_CTRL      0x38D
#define INTEL_FIXED_CTR0              0x309
#define INTEL_PERF_GLOBAL_STATUS      0x38E
#define INTEL_PERF_GLOBAL_CTRL        0x38F
#define INTEL_PERF_GLOBAL_OVF_CTRL    0x390
#define INTEL_IA32_DS_AREA	      0x600
#define INTEL_IA32_PEBS_ENABLE 	      0x3F1

#define INTEL_MSR_PERFMON_SEL0_ENABLE (1 << 22)
#define INTEL_MSR_PERFMON_SEL1_ENABLE (1 << 22)
#define INTEL_MSR_PERFMON_SEL2_ENABLE (1 << 22)

#define INTEL_FIXED_CTR0_ENABLE     (1)
#define INTEL_FIXED_CTR0_PMI        (1 << 3)
#define INTEL_OVF_PMC0              (1 << 1)
#define INTEL_OVF_FIXED_CTR0        (1)




#endif /* __ASSEMBLY__ */

#ifndef __ASSEMBLY__
/*table to store the modified process pages*/



#endif /* __ASSEMBLY__ */

#endif /* RCOUNTER_H */

