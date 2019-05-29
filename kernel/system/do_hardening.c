/* The kernel call implement in this file
 *  m_type : SYS_HARDENING
 * The parameters for this kernel call are:
 *   - HTASK_ENDPT
 *   - HTASK_TYPE
 *       - HTASK_EN_HARDENING_ALL_F : 
 *          Enable hardening for new forked process
 *       - HTASK_DIS_HARDENING_ALL_F : 
 *          Disable hardening for new forked process
 *       - HTASK_EN_HARDENING_PID: 
 *          Enable hardening for given pid process
 *       - HTASK_DIS_HARDENING_PID: 
 *          Disable hardening for given pid process
 *   - HTASK_PENDPOINT
 *   - HTASK_PNAME
 */

#include "kernel/system.h"
#include "kernel/arch/i386/include/arch_proto.h"
#include "kernel/arch/i386/hproto.h"
#include "kernel/arch/i386/htype.h"
#include <assert.h>
/*==================================================*
 *              do_hardening                        *
 *==================================================*/
int do_hardening(struct proc * caller, 
  message * m_ptr){
  proc_nr_t proc_nr, proc_nr_e, hproc_nr, hproc_nr_e;
  struct proc *p, *hp;
  message hm;
  int err;
  proc_nr_e= (proc_nr_t) m_ptr->HTASK_ENDPT;
  if (!isokendpt(proc_nr_e, &proc_nr))
         return(EINVAL);
  p = proc_addr(proc_nr);
  switch(m_ptr->HTASK_TYPE){
     case HTASK_EN_HARDENING_ALL_F:
          h_can_start_hardening = ENABLE_HARDENING;
          hm.m_source = p->p_endpoint;
          hm.m_type   = VM_TELL_VM_H_ENABLE;
          if ((err = mini_send(p, VM_PROC_NR,
			&hm, FROM_KERNEL))) {
		panic("WARNING: enable_hardening:"
                  " mini_send returned %d\n", err);
          }
          break;
     case HTASK_DIS_HARDENING_ALL_F:
          h_can_start_hardening = DISABLE_HARDENING;
          hm.m_source = p->p_endpoint;
          hm.m_type   = VM_TELL_VM_H_DISABLE;
          if ((err = mini_send(p, VM_PROC_NR,
			&hm, FROM_KERNEL))) {
		panic("WARNING: disable_hardening:"
                 " mini_send returned %d\n", err);
          }
          break;
     case HTASK_EN_HARDENING_PID:
          hproc_nr_e= (proc_nr_t) m_ptr->HTASK_P_ENDPT;
          if (!isokendpt(hproc_nr_e, &hproc_nr)) 
                return(EINVAL);
          hp = proc_addr(hproc_nr);
          hp->p_hflags |= PROC_TO_HARD;
          hm.m_source = hp->p_endpoint;
          if (priv(hp)->s_flags & SYS_PROC) 
             hm.m_type   = VM_TELL_VM_H_ENABLE_PRIV_P;
          else
             hm.m_type   = VM_TELL_VM_H_ENABLE_P;
          if ((err = mini_send(hp, VM_PROC_NR,
			&hm, FROM_KERNEL))) {
		panic("WARNING: enable_hardening:"
                 " mini_send returned %d\n", err);
          }
          break;
    case HTASK_DIS_HARDENING_PID:
          hproc_nr_e= (proc_nr_t) m_ptr->HTASK_P_ENDPT;
          if (!isokendpt(hproc_nr_e, &hproc_nr)) 
                return(EINVAL);
          hp = proc_addr(hproc_nr);
          hp->p_hflags &= ~PROC_TO_HARD;
          hm.m_source = hp->p_endpoint;
          hm.m_type   = VM_TELL_VM_H_DISABLE_P;
          if ((err = mini_send(hp, VM_PROC_NR,
			&hm, FROM_KERNEL))) {
		panic("WARNING: disable_hardening:"
                 " mini_send returned %d\n", err);
          }
     case HTASK_DISPLAY_HARDENIG:
          //if(h_can_start_hardening == ENABLE_HARDENING)
          display_hardened_proc();
          break;
  }
  return(OK);
}
