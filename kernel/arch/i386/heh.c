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

/*===============================================*
 *		hardening_exception_handler      *
 *===============================================*/
void hardening_exception_handler(
     struct exception_frame * frame){
    /*
     * running process should be the current 
     * hardenning process
     * the running process should not be the VM
     * the hardening should be enable
     * This function check if the nature of the 
     * exception. The exception is 
     * handled by hardening_exception_handler in 
     * three case
     *     - NMI, so the exception is come from 
     * the retirmen counter
     *     - MCA/MCE the exception is come from 
     * the MCA/MCE module
     *     - A pagefault occur
     * In all others cases the PE is stopped
     */
#if INJECT_FAULT__
   restore_cr_reg();
#endif
   /**This function should be called 
    * when hardening is enable**/
   assert(h_enable);
   /*get the running process*/
   struct proc  *p = get_cpulocal_var(proc_ptr);
   /**The running process should 
    * be a hardened process**/
   assert(h_proc_nr == p->p_nr);
   assert(h_proc_nr != VM_PROC_NR);
   get_remain_ins_counter_value(p);
   h_stop_pe = H_YES;
#if H_DEBUG
   printf("#### GOT EXCEPTION HAHAHA %d %d %d %d ####", 
            h_step,h_proc_nr,p->p_nr, frame->vector);
#endif
   switch(frame->vector){
      case DIVIDE_VECTOR :
           break;
      case DEBUG_VECTOR :
           if(ssh(p)!=OK)
               h_stop_pe = H_NO;
           break;
      case NMI_VECTOR :
#if H_DEBUG
           printf("#### GOT NMI HAHAHA %d %d %d####", 
            h_step,h_proc_nr,p->p_nr);
#endif
           if(irh()!=OK)
             h_stop_pe = H_NO;   
           break;
      case BREAKPOINT_VECTOR:
           break;
      case OVERFLOW_VECTOR:
           break;
      case BOUNDS_VECTOR:
           break;
      case INVAL_OP_VECTOR:
           break;
      case COPROC_NOT_VECTOR:
           break;
      case DOUBLE_FAULT_VECTOR:
           break;
      case COPROC_SEG_VECTOR:
           break;
      case INVAL_TSS_VECTOR:
           break;
      case SEG_NOT_VECTOR:
           break;
      case STACK_FAULT_VECTOR:
           break;
      case PROTECTION_VECTOR:
           break;
      case PAGE_FAULT_VECTOR :
           /**reset the hardening data**/
           /*** ADD COMMENT : TODO */
           h_normal_pf = 0;
           h_rw = 0; 
           /**read the virtual address 
            *where the page fault occurred**/
           reg_t pagefaultcr2 = read_cr2();
           /*** Check the nature of the pagefault:
            * if it is caused by hardening
            **  check_r = OK else 
            *   check_r = H_HANDLED_PF**/   
           int check_r = 
             check_vaddr_2(p,
                   (u32_t *)p->p_seg.p_cr3, 
                   pagefaultcr2, &h_rw);
           /**set hardening data to 
            * inform the kernel**/
           /***  TODO CHANGE THE COMPARISON ****/
           if(check_r==OK)
              h_stop_pe = H_NO;
           else 
             h_normal_pf = NORMAL_PF;       
           break;
      
      case COPROC_ERR_VECTOR:
           break;
      case ALIGNMENT_CHECK_VECTOR:
           break;
      case MACHINE_CHECK_VECTOR:
           if(mcah()==OK)
              h_stop_pe = H_NO;
           break;
      case SIMD_EXCEPTION_VECTOR:
           break; 
      default :
           panic("Unkown exception vector in"
             "hardening_exception_handler");
           break;

   }
   
   return;
}

