/* The kernel call implemented in this file:
 *   m_type:	SYS_FORK
 *
 * The parameters for this kernel call are:
 *   m_lsys_krn_sys_fork.endpt		
 *      (parent, process that forked)
 *   m_lsys_krn_sys_fork.slot		
 *      (child's process table slot)
 *   m_lsys_krn_sys_fork.flags		
 *       (fork flags)
 *   m_krn_lsys_sys_fork.endpt		
 *       (endpoint of the child)
 *   m_krn_lsys_sys_fork.msgaddr	
 *       (new memory map for the child)
 */

#include "kernel/system.h"
#include "kernel/vm.h"
#include <signal.h>
#include <string.h>
#include <assert.h>

#include <minix/endpoint.h>
#include <minix/u64.h>

#include "../arch/i386/htype.h"
#include "../arch/i386/hproto.h"

#if USE_FORK

/*=============================================*
 *		do_fork	                       *
 *=============================================*/
int do_fork(struct proc * caller, message * m_ptr)
{
/* Handle sys_fork().
 * m_lsys_krn_sys_fork.endpt has forked.
 * The child is m_lsys_krn_sys_fork.slot.
 */
#if defined(__i386__)
  char *old_fpu_save_area_p;
#endif
  /* child process pointer */
  register struct proc *rpc;
  /* parent process pointer */		
  struct proc *rpp;			
  int gen;
  int p_proc;
  int namelen;
  static int hcount = 0; 

  if(!isokendpt(
      m_ptr->m_lsys_krn_sys_fork.endpt, &p_proc))
	return EINVAL;

  rpp = proc_addr(p_proc);
  rpc = proc_addr(m_ptr->m_lsys_krn_sys_fork.slot);
  if (isemptyp(rpp) || ! isemptyp(rpc)) return(EINVAL);

  assert(!(rpp->p_misc_flags & MF_DELIVERMSG));

  /* needs to be receiving so we 
   * know where the message buffer is */
  if(!RTS_ISSET(rpp, RTS_RECEIVING)) {
     printf("kernel: fork not done synchronously?\n");
     return EINVAL;
  }

  /* make sure that the FPU context 
   * is saved in parent before copy */
  save_fpu(rpp);
  /* Copy parent 'proc' struct to child. 
   * And reinitialize some fields. */
  gen = _ENDPOINT_G(rpc->p_endpoint);
#if defined(__i386__)
  old_fpu_save_area_p = rpc->p_seg.fpu_state;
#endif
  /* copy 'proc' struct */
  *rpc = *rpp;				
#if defined(__i386__)
  rpc->p_seg.fpu_state = old_fpu_save_area_p;
  if(proc_used_fpu(rpp))
	memcpy(rpc->p_seg.fpu_state, 
         rpp->p_seg.fpu_state, FPU_XFP_SIZE);
#endif
  /* increase generation */
  if(++gen >= _ENDPOINT_MAX_GENERATION)	
    /* generation number wraparound */
	gen = 1;
  /* this was obliterated by copy */			
  rpc->p_nr = m_ptr->m_lsys_krn_sys_fork.slot;	
  /* new endpoint of slot */
  rpc->p_endpoint = _ENDPOINT(gen, rpc->p_nr);	
  /* child sees pid = 0 to know it is child */
  rpc->p_reg.retreg = 0;
  /* set all the accounting times to 0 */	
  rpc->p_user_time = 0;		
  rpc->p_sys_time = 0;

  rpc->p_misc_flags &=
	~(MF_VIRT_TIMER | MF_PROF_TIMER
      | MF_SC_TRACE | MF_SPROF_SEEN | MF_STEP);
  /* disable, clear the process-virtual timers */
  rpc->p_virt_left = 0;		
  rpc->p_prof_left = 0;

  /* Mark process name as being a forked copy */
  namelen = strlen(rpc->p_name);
#define FORKSTR "*F"
  if(namelen+strlen(FORKSTR) < sizeof(rpc->p_name))
	strcat(rpc->p_name, FORKSTR);

  /* the child process is not 
   * runnable until it's scheduled. */
  RTS_SET(rpc, RTS_NO_QUANTUM);
  reset_proc_accounting(rpc);

  rpc->p_cpu_time_left = 0;
  rpc->p_cycles = 0;
  rpc->p_kcall_cycles = 0;
  rpc->p_kipc_cycles = 0;

  rpc->p_tick_cycles = 0;
  cpuavg_init(&rpc->p_cpuavg);

  /* If the parent is a privileged process, 
   * take away the privileges from the 
   * child process and inhibit it from running
   *  by setting the NO_PRIV flag.
   * The caller should explicitly set the
   * new privileges before executing.
   */
  if (priv(rpp)->s_flags & SYS_PROC) {
      rpc->p_priv = priv_addr(USER_PRIV_ID);
      rpc->p_rts_flags |= RTS_NO_PRIV;
  }

  /* Calculate endpoint identifier, 
   * so caller knows what it is. */
  m_ptr->m_krn_lsys_sys_fork.endpt = rpc->p_endpoint;
  m_ptr->m_krn_lsys_sys_fork.msgaddr = 
              rpp->p_delivermsg_vir;

  /* Don't schedule process in VM mode 
   * until it has a new pagetable. */
  if(m_ptr->m_lsys_krn_sys_fork.flags & PFF_VMINHIBIT){
  	RTS_SET(rpc, RTS_VMINHIBIT);
  }

  /* 
   * Only one in group should have 
   * RTS_SIGNALED, child doesn't inherit tracing.
   */
  RTS_UNSET(rpc, (RTS_SIGNALED | 
            RTS_SIG_PENDING | RTS_P_STOP));
  (void) sigemptyset(&rpc->p_pending);

#if defined(__i386__)
  rpc->p_seg.p_cr3 = 0;
  rpc->p_seg.p_cr3_v = NULL;
#elif defined(__arm__)
  rpc->p_seg.p_ttbr = 0;
  rpc->p_seg.p_ttbr_v = NULL;
#endif
/*** Add by EKA**/
  rpc->p_setcow = 0; 
  rpc->p_hflags = 0;
  if(hprocs_in_use <= H_NPROCS_TO_START_H)
  hprocs_in_use++;
   
  if(hprocs_in_use > 800){
      rpc->p_setcow = 1; 
  }
  
  rpc->p_ticks = 0;
   
  if(h_can_start_hardening){
      rpc->p_hflags |= PROC_TO_HARD;
      hc_proc_nr[(hcount++)%10] = rpc->p_nr;
  }
  rpc->p_lus1_us2_size = 0;
  rpc->p_lus1_us2 = NULL;
  rpc->p_hardening_mem_events = NULL;
  rpc->p_nb_hardening_mem_events = 0;
  rpc->p_hardening_shared_regions = NULL;
  rpc->p_nb_hardening_shared_regions = 0;
  if(rpp->p_hflags & PROC_TO_HARD){
#if H_DEBUG
     display_mem(rpp);
#endif
     set_fork_label(rpp);
     //free_pram_mem_blocks(rpp, 0);
  }
/** End Add by EKA**/
  return OK;
}

#endif /* USE_FORK */
