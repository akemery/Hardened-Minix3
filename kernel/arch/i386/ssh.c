#include "kernel/kernel.h"
#include "kernel/vm.h"

#include <machine/vm.h>

#include <minix/type.h>
#include <minix/syslib.h>
#include <minix/cpufeature.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <stdlib.h>


#include <machine/vm.h>


#include "arch_proto.h"

#include "htype.h"
#include "hproto.h"
#include "rcounter.h"
#include "mca.h"
#include "../../clock.h"

#ifdef USE_APIC
#include "apic.h"
#ifdef USE_WATCHDOG
#include "kernel/watchdog.h"
#endif
#endif

int ssh(struct proc *p){
   origin_syscall = PE_END_IN_NMI;
   p->p_reg.psw &= ~TRACEBIT;
   save_context(p);
#if H_DEBUG
   printf("#### GOT DEBUG HAHAHA %d %d %d 0x%x####\n", 
             h_step,h_proc_nr,p->p_nr, p->p_reg.psw);
#endif
           if(h_step==FIRST_STEPPING)
              first_run_ins++;
           else
              secnd_run_ins++;
           if( secnd_run_ins!= first_run_ins ){
               h_stop_pe = H_NO;
               p->p_misc_flags |= MF_STEP;
               h_unstable_state = H_STEPPING;
               p->p_reg.psw &= ~TRACEBIT;
               return(EFAULT);
            }
            else{
#if H_DEBUG
               printf("#### END DEBUG HAHAHA (3) %d 0x%x 0%x 0x%x####\n", 
             h_step,secnd_run_ins,first_run_ins, p->p_reg.psw);
#endif
               p->p_misc_flags &= ~MF_STEP;
               h_unstable_state = H_STEPPING;
               p->p_reg.psw &= ~TRACEBIT;
               if(h_step==FIRST_STEPPING)
                  h_step=SECOND_RUN;
               return(OK);
            }
  
}

void ssh_init(struct proc *p){
  if(secnd_run_ins < first_run_ins){
#if H_DEBUG
   printf("Stepping start from (2) 0x%x to 0x%x\n",
        secnd_run_ins, first_run_ins);
#endif
     p->p_misc_flags |= MF_STEP;
     h_unstable_state = H_STEPPING;
     return;
  }

  if(secnd_run_ins > first_run_ins){
#if H_DEBUG
      printf("Stepping start from (1) 0x%x to 0x%x\n",
          first_run_ins, secnd_run_ins  );
#endif
    vm_reset_pram(p, (u32_t *)p->p_seg.p_cr3, 
                 CPY_RAM_FIRST_STEPPING); 
    restore_for_stepping_first_run(p);
    p->p_misc_flags |= MF_STEP;
    h_unstable_state = H_STEPPING;
    h_step = FIRST_STEPPING;
    return;
  }


}
