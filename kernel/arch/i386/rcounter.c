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

#define PMC_IRQ          230


static uint32_t low, high;
/* interrupt handler hook intel_arch_insn_counter_int */
static irq_hook_t pic_intel_arch_insn_counter_hook;		

int register_intel_arch_insn_counter_int_handler(const irq_handler_t handler){
  /* Using PIC, Initialize the PMC  interrupt hook. */
  pic_intel_arch_insn_counter_hook.proc_nr_e = NONE;
  pic_intel_arch_insn_counter_hook.irq = PMC_IRQ;
  put_irq_handler(&pic_intel_arch_insn_counter_hook, PMC_IRQ, handler);
  return(OK);
}

int intel_arch_insn_counter_int_handler(){
   ia32_msr_read(INTEL_MSR_PERFMON_CRT1, &high, &low);
   ia32_msr_read(INTEL_PERF_GLOBAL_STATUS, &high, &low);
   if(low & INTEL_OVF_PMC0){
     ia32_msr_write(INTEL_PERF_GLOBAL_OVF_CTRL, 0, 2);
     lapic_write(LAPIC_LVTPCR, PMC_IRQ);
   }
   return(OK);
}

#if 0
void lapic_set_insn_handlers(void){
   int_gate_idt(PMC_IRQ, (vir_bytes) lapic_intel_arch_insn_counter_int_handler,
	PRESENT | INT_GATE_TYPE | (INTR_PRIVILEGE << DPL_SHIFT));
}
#endif

void intel_arch_insn_counter_init(void){
  u32_t val = 0;
  ia32_msr_write(INTEL_MSR_PERFMON_CRT1, 0, 0);
  /*Int, OS, USR, Instruction retired*/
  val = 1 << 20 | 1 << 16 | 0xc0;
  ia32_msr_write(INTEL_MSR_PERFMON_SEL1, 0, val);
  ia32_msr_write(INTEL_MSR_PERFMON_SEL1, 0,
	val | INTEL_MSR_PERFMON_SEL1_ENABLE);
  /* unmask the performance counter interrupt. Enable NMI*/
  lapic_write(LAPIC_LVTPCR, APIC_ICR_DM_NMI);
}

void intel_arch_insn_counter_reinit(void){
  lapic_write(LAPIC_LVTPCR, APIC_ICR_DM_NMI); /*Pour activer le NMI*/
	ia32_msr_write(INTEL_MSR_PERFMON_CRT1, 0, 0);
}

void intel_fixed_insn_counter_init(void){
  u32_t val = 0;
  ia32_msr_write(INTEL_FIXED_CTR0, 0, 0);
  val = 1 << 3 | 1 << 1;
  ia32_msr_write(INTEL_MSR_FIXED_CTR_CTRL, 0, val);
  /* unmask the performance counter interrupt. Enable NMI */
  lapic_write(LAPIC_LVTPCR, APIC_ICR_DM_NMI); 
}

void intel_fixed_insn_counter_reset(void){
    ia32_msr_write(INTEL_MSR_FIXED_CTR_CTRL, 0, 0);
}

void intel_arch_insn_counter_reset(void){
   ia32_msr_write(INTEL_MSR_PERFMON_SEL1, 0, 0);
}


void intel_fixed_insn_counter_enable(void){
   u32_t val = 0;
   val = 1 << 3 | 1 << 1;
   ia32_msr_write(INTEL_MSR_FIXED_CTR_CTRL, 0, val);
}

void intel_arch_insn_counter_enable(void){
   u32_t val = 0;
   val = 1 << 20 | 1 << 16 | 0xc0;
   ia32_msr_write(INTEL_MSR_PERFMON_SEL1, 0, val);
   ia32_msr_write(INTEL_MSR_PERFMON_SEL1, 0,
			val | INTEL_MSR_PERFMON_SEL1_ENABLE);
}

void reset_counter(void){
/**OFF the retirement counter when the running process is not a PE**/
#if USE_FIX_CTR
   intel_fixed_insn_counter_reset();
#else
  intel_arch_insn_counter_reset();
#endif
}

void enable_counter(void){
/**ON the retirement counter when the running process is a PE**/
#if USE_FIX_CTR
  intel_fixed_insn_counter_enable();
#else
  intel_arch_insn_counter_enable();
#endif

}

void intel_fixed_insn_counter_reinit(void)
{
  lapic_write(LAPIC_LVTPCR, APIC_ICR_DM_NMI); /*Pour activer le NMI*/
  ia32_msr_write(INTEL_FIXED_CTR0, 0, 0);
}

void read_ins_64(u64_t* t){
	u32_t lo, hi;
#if USE_FIX_CTR
  ia32_msr_read(INTEL_FIXED_CTR0, &hi, &lo);
#else
  ia32_msr_read(INTEL_MSR_PERFMON_CRT1, &hi, &lo);
#endif
  *t = make64 (lo, hi);
}

void update_ins_ctr_switch (){
 /** Read the retirement counter value and update the global variable 
  ** __ins_ctr_switch **/
   u64_t ins;
   u64_t * __ins_ctr_switch = get_cpulocal_var_ptr(ins_ctr_switch);
   read_ins_64(&ins);
   *__ins_ctr_switch = ins;
}


void set_remain_ins_counter_value(struct proc *p){
  intel_arch_insn_counter_reinit();
  if(p->p_start_count_ins){
#if USE_FIX_CTR
    ia32_msr_write(INTEL_FIXED_CTR0, 
           ex64hi(p->p_remaining_ins), ex64lo(p->p_remaining_ins));
#else
    ia32_msr_write(INTEL_MSR_PERFMON_CRT1,
           ex64hi(p->p_remaining_ins), ex64lo(p->p_remaining_ins));
#endif
    make_zero64(p->p_remaining_ins);

  }
  else{
#if USE_FIX_CTR
     ia32_msr_write(INTEL_FIXED_CTR0, 0xff,
	INS_THRESHOLD-ex64lo(INS_2_EXEC)+1);
#else
     ia32_msr_write(INTEL_MSR_PERFMON_CRT1, 0xffff,
	INS_THRESHOLD-ex64lo(INS_2_EXEC)+1);
#endif
     p->p_start_count_ins = 1;

  }
  update_ins_ctr_switch ();
}

void set_remain_ins_counter_value_0(struct proc *p){
/** Before starting one of the executions of the PE, this function
  ** initializes the retirement counter to
  ** (Overflow value - Maximum number of instruction of the PE) **/
#if USE_FIX_CTR
   ia32_msr_write(INTEL_FIXED_CTR0, INS_THRESHOLD,
	INS_THRESHOLD-ex64lo(INS_2_EXEC)+1);
#else
     ia32_msr_write(INTEL_MSR_PERFMON_CRT1, INS_THRESHOLD,
	INS_THRESHOLD-ex64lo(INS_2_EXEC)+1);
#endif
         p->p_start_count_ins = 1;
         update_ins_ctr_switch ();
         get_remain_ins_counter_value(p);
}

void set_remain_ins_counter_value_1(struct proc *p){
/** Before resuming the PE after an interrupt or exception, this
  ** function updates the retirement counter to the value
  ** saved in p_remaining_ins**/

#if USE_FIX_CTR
   ia32_msr_write(INTEL_FIXED_CTR0, ex64hi(p->p_remaining_ins),
                             ex64lo(p->p_remaining_ins));
#else
   ia32_msr_write(INTEL_MSR_PERFMON_CRT1,
		   ex64hi(p->p_remaining_ins), ex64lo(p->p_remaining_ins));
#endif
   make_zero64(p->p_remaining_ins);
   update_ins_ctr_switch ();
}


void get_remain_ins_counter_value(struct proc *p){
/** The PE is stopped read the value of the retriement counter
 ** Store that value in __ins_ctr_switch and p_remaining_ins
 ** 2 storages to keep track of the remaining instructions of the PE **/
   u64_t ins;
   u64_t * __ins_ctr_switch = get_cpulocal_var_ptr(ins_ctr_switch);
   read_ins_64(&ins);
   *__ins_ctr_switch = ins;
   p->p_remaining_ins =ins;
}



int handle_ins_counter_over(void){
/** Handle the NMI:
 ** -- Clear the overflow flag
 ** -- Reinit the NMI
 ** -- Make tke PE not runnable
 **/
  struct proc * p = get_cpulocal_var(proc_ptr);
  ia32_msr_read(INTEL_PERF_GLOBAL_STATUS, &high, &low);
#if USE_FIX_CTR
  if(high & INTEL_OVF_FIXED_CTR0){
#else
  if(low & INTEL_OVF_PMC0){
#endif
      /**the counter overflowed try to clear register's flags**/
#if USE_FIX_CTR
      ia32_msr_write(INTEL_PERF_GLOBAL_OVF_CTRL,  INTEL_OVF_FIXED_CTR0, 0);
      intel_fixed_insn_counter_reinit();
#else
      ia32_msr_write(INTEL_PERF_GLOBAL_OVF_CTRL, 0, INTEL_OVF_PMC0);
      intel_arch_insn_counter_reinit();
#endif
       return(OK);
   }
   return(EFAULT);
}
