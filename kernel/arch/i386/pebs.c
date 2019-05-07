#include "kernel/kernel.h"
#include "kernel/watchdog.h"
#include "arch_proto.h"
#include "glo.h"
#include <minix/minlib.h>
#include <minix/u64.h>

#include "apic.h"
#include "apic_asm.h"
#include "rcounter.h"
#include "hproto.h"
#include "pebs.h"

void pebs_init(void){

   pds_area[0].bts_buffer_base 		= 0;
   pds_area[0].bts_index			= 0;
   pds_area[0].bts_absolute_maximum	= 0;
   pds_area[0].bts_interrupt_threshold	= 0;
   pds_area[0].pebs_buffer_base		= ppebs;
   pds_area[0].pebs_index			= ppebs;
   pds_area[0].pebs_absolute_maximum	= ppebs + 
                                       (N_PEBS_RECORDS-1) * sizeof(struct pebs);
   pds_area[0].pebs_interrupt_threshold	= ppebs + 
                                       (N_PEBS_RECORDS+1) * sizeof(struct pebs);
   pds_area[0].pebs_counter0_reset	= INS_THRESHOLD-INS_2_EXEC;
   pds_area[0].pebs_counter1_reset	= INS_THRESHOLD-INS_2_EXEC;
   pds_area[0].reserved			= 0;

   ia32_msr_write(INTEL_PERF_GLOBAL_CTRL, 0, 0);			// known good state.
   ia32_msr_write(INTEL_IA32_DS_AREA, 0, (u32_t) &pds_area);
   ia32_msr_write(INTEL_IA32_PEBS_ENABLE, ex64hi(0xf | ((u64_t)0xf << 32)),
                        ex64lo(0xf | ((u64_t)0xf << 32)) );	// Figure 18-14.
   ia32_msr_write(INTEL_MSR_PERFMON_CRT0, INS_THRESHOLD, INS_THRESHOLD-INS_2_EXEC);
   u32_t val = 1 << 20 | 1 << 16 | 1 << 22 | 0xc0;
   ia32_msr_write(INTEL_MSR_PERFMON_SEL0 , 0, val);
   ia32_msr_write(INTEL_PERF_GLOBAL_CTRL, 0 ,0xf);
   ia32_msr_write(INTEL_PERF_GLOBAL_CTRL, 0, 0x0);
}
