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
static void update_step(int step, int p_nr, const char *from);
static void save_copy_0(struct proc* p);
static void restore_copy_0(struct proc* p);
static void restore_copy_1(struct proc* p);
static void save_copy_2(struct proc *p);
static int cmp_mem(struct proc *p);
static int cmp_reg(struct proc *p);
static void save_copy_1(struct proc *p);

void start_dwc(struct proc *p){
   /* Added by EKA*/
	
  /* Here the system is switching from 
   * kernel space to user space
   * -- If we are not runnning a hardened PE, 
   *         if the runnable process is hardened, 
   *         a new PE must be started
   *     $$$ h_enable = 1 and h_proc_nr = p->p_nr
   *     $$$ initialize the retirement counter
   *     $$$ turn on ON the retirement counter 
   * -- else if we are running a hardened PE
   *         (then h_enable is true)
   *     $$$ if the runnable process is not 
   *         hardened  or VM, panic
   *     $$$ if the runnable process is VM, turn  OFF
   *         the retirement counter
   *     $$$ if the runnable process is hardened turn
   *         on the retirement
   *         counter.
   * -- else an unhardened process has been scheduled, 
   *         then just do what classical minix does            
   */
  if((h_enable == H_DISABLE)  && 
           (p->p_nr != VM_PROC_NR) &&
            (p->p_hflags & PROC_TO_HARD)){
    /* start a new PE */
    /* be sure that no process is 
     * already in the hardening execution */
     assert(h_wait_vm_reply == H_NO);
     assert(h_step == NO_HARD_RUN); 
    /* remember the process in the 
     * hardening execution */
     h_proc_nr = p->p_nr; 
     /**That is the start of the 1st run**/
     update_step(FIRST_RUN, p->p_nr, 
       "starting pe from arch_system: First run");
     /*set the next running process frames to RO*/
     //vm_setpt_root_to_ro(p, (u32_t *)p->p_seg.p_cr3);
      set_pe_mem_to_ro(p, (u32_t *)p->p_seg.p_cr3);
     /* Save the initial state of the 
      * process in the kernel*/
      save_copy_0(p); 
#if USE_INS_COUNTER
        /* initialize retirement counter */
	set_remain_ins_counter_value_0(p);
#endif
           /* enable the hardening */
           h_enable = H_ENABLE;
#if INJECT_FAULT
      if(could_inject == H_YES){
                printf("WARNING ERROR "
           "INJECTED DURING 1ST RUN\n");
#if 0
           inject_error_in_all_cr(p);
#endif
           inject_error_in_gpregs(p);
           could_inject = H_NO;
       }
#endif
  }
  if((h_enable == H_ENABLE)  &&
        ( (h_restore == RESTORE_FOR_SECOND_RUN) ||
           (h_restore == RESTORE_FOR_FISRT_RUN) ) ){ 
      /* besure it is the hardening PE*/
      assert(h_proc_nr == p->p_nr); 
      /* save the working set, the woring set 
         size list before restoring*/
      struct pram_mem_block * pmb = p->p_lus1_us2;
      int lus1_us2_size = 
             p->p_lus1_us2_size; 
      /* restore the initial state 
       * (context and kernel state data */
      restore_copy_0(p);
      /* save the working set, the woring set 
       * size list after restoring */
      p->p_lus1_us2 = pmb;
      p->p_lus1_us2_size = 
               lus1_us2_size;             
     /* Two possibilities of restoring
      * 1- The Processing run correctly the first
      *     run and we have 
      *     to continue to the second run
      * 2- An error occurs, so we have to restore
      *     to the previous state and restart 
      *     the first run **/     
     switch(h_restore){ 
       case RESTORE_FOR_SECOND_RUN:
         /* update the hardening step variables 
         * to 2nd run*/
         update_step(SECOND_RUN, p->p_nr, 
              "restoring arch_system");
         break;
       case RESTORE_FOR_FISRT_RUN:
         update_step(FIRST_RUN, p->p_nr, 
              "restoring arch_system");
         break;
       default:
         panic("UNKOWN RESTORING STATE");
     }         
    /* reset the hardening state variables. 
     * The restoring goes well*/
    /**Restoring to start the second run**/
    /* set all data pages as not accessible */   
    //vm_setpt_root_to_ro(p, (u32_t *)p->p_seg.p_cr3);
     set_pe_mem_to_ro(p, (u32_t *)p->p_seg.p_cr3);
     h_restore = 0;
     /* be sure the process remain runnable*/
     assert(proc_is_runnable(p)); 
#if INJECT_FAULT 
    if(could_inject == H_YES){
      printf("WARNING ERROR INJECTED "
             "DURING 2ND RUN\n");
#if 0
        inject_error_in_all_cr(p);
#endif
        inject_error_in_gpregs(p);
        could_inject = H_NO;
      }
#endif
  }
  if(h_enable && (h_proc_nr != p->p_nr) &&
           (p->p_nr != VM_PROC_NR) )
   /*Should never happen*/
    panic("Interference in the hardening"
           " task by: %d", p->p_nr);
   /* Should never happen. VM should run only 
    * when the hardened process
    * trigger a page fault */
   if(h_enable && (p->p_nr == VM_PROC_NR) &&
     !RTS_ISSET(proc_addr(h_proc_nr), RTS_PAGEFAULT)&& 
     (h_step != VM_RUN))
    panic("Le VM tente de s'exécuter "
       "sans une page fault %d\n", h_step);
#if USE_INS_COUNTER
   if((h_enable == H_ENABLE) && 
        (p->p_nr == h_proc_nr)){
   /* we resume the current hardened PE 
    * restore value of retirement counter 
    * saved when the system switched
    * from the hardened PE context to 
    * kernel context */
       set_remain_ins_counter_value_1(p);
       enable_counter();
    }
    else /* a process which is not 
          * hardened has been selected by 
                the scheduler */
      reset_counter();
#endif
    /** Ensure that when we are in step 1 or
     ** 2 only The PE can run**/
    if((h_enable == H_ENABLE) && 
        ((h_step == FIRST_RUN) || 
            (h_step == SECOND_RUN)))
       assert(h_proc_nr == p->p_nr);
    
     /** when vm_should_run || h_step == VM_RUN 
       **is the turn of VM to run **/
    if((h_enable == H_ENABLE) && ((h_step == VM_RUN)
          || vm_should_run))
           assert(VM_PROC_NR == p->p_nr);
/**End Added by EKA**/


}

/*==============================================*
 *			hardening_task          *
 *==============================================*/
void hardening_task(void){
    /*
     * This function is called to end the PE execution.
     * Either the 1st execution it should start 
     *  the second execution
     * Either the 2nd execution 
     *  it should start the comprison phase
     * running process should be the current
     *  hardenning process
     * The running process should not be the VM
     * The hardening should be enable
     */
#if INJECT_FAULT
    restore_cr_reg();
#endif
    assert(h_enable);
    struct proc  *p = get_cpulocal_var(proc_ptr);
    assert(h_proc_nr == p->p_nr);
    assert(h_proc_nr != VM_PROC_NR);
    /* Should only be called during 1st or 2nd run */
    assert((h_step == FIRST_RUN) || 
       (h_step == SECOND_RUN)); 
    save_context(p);
    if(h_step == FIRST_RUN){ 
       /* End of the 1st execution */
       assert(h_restore==0);
       /* remember to restore the state 0 */
       h_restore = RESTORE_FOR_SECOND_RUN; 
       /* set the page in the working set to first_phys
        *copy the content of us0 to us1 and the content 
        * of pram2_phys to us0*/
       vm_reset_pram(p, (u32_t *)p->p_seg.p_cr3, 
           CPY_RAM_FIRST); 
       /* launch the second run */
#if H_DEBUG
       printf("ENDING FISRT RUN %d %d\n", 
         p->p_nr, origin_syscall);
#endif
       run_proc_2(p);
       /*not reachable go directly to 
        the hardening process */
       NOT_REACHABLE;
    }
    else if(h_step == SECOND_RUN){
#if H_DEBUG
          printf("ENDING SECOND RUN %d %d\n", 
            p->p_nr, origin_syscall);
#endif
          if((origin_syscall == PE_END_IN_NMI) &&
               !cmp_reg(p)){
             ssh_init(p);
             return;
          }
          /* comparison of context1 and context 2. 
           * Here we compare the saved 
           * registers */
          if(!cmp_reg(p) || cmp_mem(p)!=OK){
          /* That means the system is in unstable state
           *  because the comparison stage failed.
           *  The solution is to cancel all 
           *  thing that fault
           * trigger in the system. The main 
           * objective is to
           * keep the effect of that event 
           * in the kernel.
           * it should certainly not be spread 
           * to the rest of the system**/
             h_unstable_state = H_UNSTABLE;
#if H_DEBUG
             printf("context non identique %d %d\n",
               p->p_endpoint, h_normal_pf);
#endif
             vm_reset_pram(p,(u32_t *)p->p_seg.p_cr3,
                 CMP_FAILED);
             h_restore = RESTORE_FOR_FISRT_RUN;
             /** Prevent the PE from running**/
             p->p_rts_flags |= RTS_UNSTABLE_STATE;
             nbpe_f++;
             return;
          }
          
       /* copy of us2 to us0 */
       vm_reset_pram(p,(u32_t *)p->p_seg.p_cr3,
               CPY_RAM_PRAM);

      /* reset of hardening global variables */
       h_enable = 0;
       h_proc_nr = 0;
       h_step_back = 0;
       h_step = 0;
       h_do_sys_call = 0;
       h_do_nmi = 0;
       vm_should_run = 0;
       pe_should_run = 0;
       h_restore = 0; 
       h_normal_pf = 0;
       h_pf_handle_by_k = 0;
        /** The system is in stable state**/
       h_unstable_state = H_STABLE; 
       /** a normal page fault occur 
        * where the pqge is not in the working set**/
       
       h_rw = 0; 
        /** Reset the instruction counter process**/
       p->p_start_count_ins = 0;
       id_current_pe++; // Comment TODO
       pagefault_addr_1 = 0;
       pagefault_addr_2 = 0;
       nbpe++;
#if H_DEBUG_2
       printf("PE OK #ws: %d #us1_us2: %d nbpe: %d\n",
            p->p_workingset_size,
                       p->p_lus1_us2_size, nbpe);
#endif
       return;
   }
   else{
      panic("UNKOWN HARDENING STEP %d\n", h_step);
   }
      
}

/*===============================================*
 *				cmp_mem          *
 *===============================================*/

static int cmp_mem(struct proc *p){
   if(p->p_lus1_us2_size <= 0)
          return(OK);
   int r = OK;
   struct pram_mem_block *pmb = p->p_lus1_us2;
   p->p_workingset_size = 0;
     while(pmb){
      if((pmb->us2 == MAP_NONE) || 
          (pmb->us1 == MAP_NONE)){
           pmb = pmb->next_pmb;
           continue;
      }    
      if(pmb->flags & FWS){
         if((r = cmp_frames(pmb->us2, pmb->us1))!=OK){
            printf("&&& diff vaddr 0x%lx pram 0x%lx "
              " temp 0x%lx 0x%lx\n", pmb->vaddr,
                 pmb->us0, pmb->us1, pmb->us2);
            return (r);
         }
         p->p_workingset_size++;
         pmb->flags &= ~FWS;
#if H_DEBUG
         printf("IN FINAL WORKING SET 0x%lx pram 0x%lx " 
                     "first 0x%lx second 0x%lx\n",
                 pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2);
#endif
      }
      pmb = pmb->next_pmb;
     }
    return (r);
}

/*===========================================*
 *				cmp_reg      *
 *===========================================*/
static int cmp_reg(struct proc *p){
   /** Compare registers from first run and second run
    ** If one pair of register is different the return
    *  value is 0
    ** Otherwise the return value is non NULL
    ** The function compares also the origin of the 
    *  trap, fault, or interrupt
    ** for the two runs. If they are not the same, 
    *  the return value is 0***/
#if H_DEBUG
   printf("****in cmp back (current) p %d"
	" gs 0x%x fs 0x%x es 0x%x ds 0x%x di 0x%x\n"
	" si 0x%x fp 0x%x bx 0x%x****\n "
	" dx 0x%x cx 0x%x retreg 0x%x  pc 0x%x"
        " cs 0x%x\n"
	" psw 0x%x sp 0x%x ss 0x%x ****\n",
	p->p_endpoint,
	p->p_reg.gs,
	p->p_reg.fs,
	p->p_reg.es,
	p->p_reg.ds,
	p->p_reg.di,
	p->p_reg.si,
	p->p_reg.fp,
	p->p_reg.bx,
	p->p_reg.dx,
	p->p_reg.cx,
	p->p_reg.retreg,
	p->p_reg.pc,
	p->p_reg.cs,
	p->p_reg.psw,
	p->p_reg.sp,
	p->p_reg.ss);
    printf("****in cmp back (:1) p %d\n"
	"gs 0x%x fs 0x%x es 0x%x ds 0x%x di 0x%x\n"
	"si 0x%x fp 0x%x  bx 0x%x****\n "
	"dx 0x%x cx 0x%x retreg 0x%x  pc 0x%x "
        "cs 0x%x\n"
	"psw 0x%x sp 0x%x ss 0x%x ****\n"
        "eax 0x%x ebx 0x%x ecx 0x%x edx 0x%x esi "
        "0x%x edi 0x%x\n"
        "esp 0x%x ebp 0x%x origin %d\n",
	p->p_endpoint,
	gs_1,
	fs_1,
	es_1,
	ds_1,
	di_1,
	si_1,
	fp_1,
	bx_1,
	dx_1,
	cx_1,
	retreg_1,
	pc_1,
	cs_1,
	psw_1,
	sp_1,
	ss_1,
        eax_s1,
        ebx_s1,
        ecx_s1,
        edx_s1,
        esi_s1,
        edi_s1,
        esp_s1,
        ebp_s1,
        origin_1);

     printf("****in cmp back (:2) p %d\n"
	"gs 0x%x fs 0x%x es 0x%x ds 0x%x di 0x%x\n"
	"si 0x%x fp 0x%x  bx 0x%x****\n "
	"dx 0x%x cx 0x%x retreg 0x%x pc 0x%x cs 0x%x\n"
	"psw 0x%x sp 0x%x ss 0x%x****\n"
        "eax 0x%x ebx 0x%x ecx 0x%x edx 0x%x esi"
        " 0x%x edi 0x%x\n"
        "esp 0x%x ebp 0x%x origin %d\n",
	p->p_endpoint,
	gs_2,
	fs_2,
	es_2,
	ds_2,
	di_2,
	si_2,
	fp_2,
	bx_2,
	dx_2,
	cx_2,
	retreg_2,
	pc_2,
	cs_2,
	psw_2,
	sp_2,
	ss_2,
        eax_s2,
        ebx_s2,
        ecx_s2,
        edx_s2,
        esi_s2,
        edi_s2,
        esp_s2,
        ebp_s2,
        origin_2);
#endif
   return (
        (gs_1 == gs_2) &&
	(fs_1 == fs_2) &&
	(es_1 == es_2) &&
	(ds_1 == ds_2) &&
	(di_1 == di_2) &&
	(si_1 == si_2) &&
	(fp_1 == fp_2) &&
	(bx_1 == bx_2) &&
	(dx_1 == dx_2) &&
	(cx_1 == cx_2) &&
	(retreg_1 == retreg_2) &&
	(pc_1 == pc_2) &&
	(cs_1 == cs_2) &&
	(psw_1 == psw_2) &&
	(sp_1 == sp_2)   &&
	(ss_1 == ss_2)   &&
        (origin_1 == origin_2) &&
        (eax_s1 == eax_s2) &&
        (ebx_s1 == ebx_s2) &&
        (ecx_s1 == ecx_s2) &&
        (edx_s1 == edx_s2) &&
        (esi_s1 == esi_s2) &&
        (edi_s1 == edi_s2) &&
        (esp_s1 == esp_s2) &&
        (ebp_s1 == ebp_s2) &&
        (pagefault_addr_1 == pagefault_addr_2) &&
        (cr0_1 == cr0_2) &&
        (cr2_1 == cr2_2) &&
        (cr3_1 == cr3_2) &&
        (cr4_1 == cr4_2) 
     );
}

void save_context(struct proc *p){
   if(h_step == FIRST_RUN)
      save_copy_1(p);
   if(h_step == SECOND_RUN)
      save_copy_2(p);
}

/*===========================================*
 *				run_proc_2   *
 *===========================================*/
void run_proc_2(struct proc *p)
{
    /* This the standard switch_to_user 
     * function of Minix 3 without
     * kernel verification already performed 
     * before FIRST RUN
     */
    /* update the global variable "get_cpulocal_var" 
     * which is a Minix Macro
     */
	get_cpulocal_var(proc_ptr) = p;

	switch_address_space(p);
        /** Stop counting CPU cycle for the KERNEL**/
	context_stop(proc_addr(KERNEL));

#if defined(__i386__)
  	assert(p->p_seg.p_cr3 != 0);
#elif defined(__arm__)
	assert(p->p_seg.p_ttbr != 0);
#endif	
	restart_local_timer();

	/*
	 * restore_user_context() carries out the 
         * actual mode switch from kernel
	 * to userspace. This function does not return
	 */
	restore_user_context(p);
	NOT_REACHABLE;
}

/*============================================*
 *		update_step                   *
 *============================================*/
static void update_step(int step, int p_nr, const char *from){
   /**Change the hardening step to step**/
#if H_DEBUG
   printf("changing step from %s for %d "
          "last step %d new step %d\n", 
           from, p_nr, h_step, step);
#endif
   h_step = step;
}

/*==============================================*
 *		save_copy_0                     *
 *==============================================*/
static void save_copy_0(struct proc* p){
   gs = (u16_t)p->p_reg.gs;
   fs = (u16_t)p->p_reg.fs;
   es = (u16_t)p->p_reg.es;
   ds = (u16_t)p->p_reg.ds;
   di = (reg_t)p->p_reg.di;
   si = (reg_t)p->p_reg.si;
   fp = (reg_t)p->p_reg.fp;
   bx = (reg_t)p->p_reg.bx;
   dx = (reg_t)p->p_reg.dx;
   cx = (reg_t)p->p_reg.cx;
   retreg = (reg_t)p->p_reg.retreg;
   pc = (reg_t)p->p_reg.pc;
   psw = (reg_t)p->p_reg.psw;
   sp = (reg_t)p->p_reg.sp;
   cs = (reg_t)p->p_reg.cs;
   ss = (reg_t)p->p_reg.ss;
   p_kern_trap_style = 
       (int) p->p_seg.p_kern_trap_style;
   p_rts_flags = p->p_rts_flags;
   cr0 = read_cr0();
   cr2 = read_cr2();
   cr3 = read_cr3();
   cr4 = read_cr4();	 
}

/*==============================================*
 *			restore_copy_0          *
 *==============================================*/
static void restore_copy_0(struct proc* p){
   p->p_reg.gs = (u16_t)gs;
   p->p_reg.fs = (u16_t)fs;
   p->p_reg.es = (u16_t)es;
   p->p_reg.ds = (u16_t)ds;
   p->p_reg.di = (reg_t)di;
   p->p_reg.si = (reg_t)si;
   p->p_reg.fp = (reg_t)fp;
   p->p_reg.bx = (reg_t)bx;
   p->p_reg.dx = (reg_t)dx;
   p->p_reg.cx = (reg_t)cx;
   p->p_reg.psw = (reg_t)psw;
   p->p_reg.sp = (reg_t)sp;
   p->p_reg.pc = (reg_t)pc;
   p->p_reg.cs = (reg_t)cs;
   p->p_reg.ss = (reg_t)ss;
   p->p_reg.retreg = (reg_t)retreg;
   p->p_seg.p_kern_trap_style = 
             (int)p_kern_trap_style;
   p->p_rts_flags = p_rts_flags;
   write_cr0(cr0);
   write_cr3(cr3);
   write_cr4(cr4);	
}

/*===========================================*
 *				save_copy_1  *
 *===========================================*/
static void save_copy_1(struct proc *p){
   gs_1 = p->p_reg.gs;
   fs_1 = p->p_reg.fs;
   es_1 = p->p_reg.es;
   ds_1 = p->p_reg.ds;
   di_1 = p->p_reg.di;
   si_1 = p->p_reg.si;
   fp_1 = p->p_reg.fp;
   bx_1 = p->p_reg.bx;
   dx_1 = p->p_reg.dx;
   cx_1 = p->p_reg.cx;
   retreg_1 = p->p_reg.retreg;
   pc_1 = p->p_reg.pc;
   cs_1 = p->p_reg.cs;
   psw_1 = p->p_reg.psw;
   sp_1 = p->p_reg.sp;
   ss_1 = p->p_reg.ss;
   p_kern_trap_style_1 = 
        (int) p->p_seg.p_kern_trap_style;
   origin_1 = origin_syscall;
   eax_s1 = eax_s;
   ebx_s1 = ebx_s;
   ecx_s1 = ecx_s;
   edx_s1 = edx_s;
   esi_s1 = esi_s;
   edi_s1 = edi_s;
   esp_s1 = esp_s;
   ebp_s1 = ebp_s;
   cr0_1  = read_cr0();
   cr2_1  = read_cr2();
   cr3_1  = read_cr3();
   cr4_1 =  read_cr4();
}


/*==========================================*
 *				save_copy_2 *
 *==========================================*/
static void save_copy_2(struct proc *p){
   gs_2 = p->p_reg.gs;
   fs_2 = p->p_reg.fs;
   es_2 = p->p_reg.es;
   ds_2 = p->p_reg.ds;
   di_2 = p->p_reg.di;
   si_2 = p->p_reg.si;
   fp_2 = p->p_reg.fp;
   bx_2 = p->p_reg.bx;
   dx_2 = p->p_reg.dx;
   cx_2 = p->p_reg.cx;
   retreg_2 = p->p_reg.retreg;
   pc_2 = p->p_reg.pc;
   cs_2 = p->p_reg.cs;
   psw_2 = p->p_reg.psw;
   sp_2 = p->p_reg.sp;
   ss_2 = p->p_reg.ss;
   p_kern_trap_style_2 = 
       (int) p->p_seg.p_kern_trap_style;
   origin_2 = origin_syscall;
   eax_s2 = eax_s;
   ebx_s2 = ebx_s;
   ecx_s2 = ecx_s;
   edx_s2 = edx_s;
   esi_s2 = esi_s;
   edi_s2 = edi_s;
   esp_s2 = esp_s;
   ebp_s2 = ebp_s;
   cr0_2  = read_cr0();
   cr2_2  = read_cr2();
   cr3_2  = read_cr3();
   cr4_2  = read_cr4();
}

/*=============================================*
 *				restore_copy_1 *
 *=============================================*/
static void restore_copy_1(struct proc* p){
  p->p_reg.gs = (u16_t)gs_1;
  p->p_reg.fs = (u16_t)fs_1;
  p->p_reg.es = (u16_t)es_1;
  p->p_reg.ds = (u16_t)ds_1;
  p->p_reg.di = (reg_t)di_1;
  p->p_reg.si = (reg_t)si_1;
  p->p_reg.fp = (reg_t)fp_1;
  p->p_reg.bx = (reg_t)bx_1;
  p->p_reg.dx = (reg_t)dx_1;
  p->p_reg.cx = (reg_t)cx_1;
  p->p_reg.retreg = (reg_t)retreg_1;
  p->p_reg.pc = (reg_t)pc_1;
  p->p_reg.cs = (reg_t)cs_1;
  p->p_reg.psw = (reg_t)psw_1;
  p->p_reg.sp = (reg_t)sp_1;
  p->p_reg.ss = (reg_t)ss_1;
  p->p_seg.p_kern_trap_style = (int)p_kern_trap_style_1;
  write_cr0(cr0_1);
  write_cr3(cr3_1);
  write_cr4(cr4_1);		
}

void restore_for_stepping_first_run(struct proc *p){
   /* save the working set, the woring 
    * set size list before restoring*/
   struct pram_mem_block * pmb = 
         p->p_lus1_us2;
   int lus1_us2_size = 
        p->p_lus1_us2_size; 
   restore_copy_1(p);
   /* save the working set, the woring 
    set size list after restoring */
   p->p_lus1_us2 = pmb;
   p->p_lus1_us2_size = 
       lus1_us2_size; 
   p->p_cpu_time_left = 
        ms_2_cpu_time(p->p_quantum_size_ms);
   /* be sure the process remain runnable*/
}
