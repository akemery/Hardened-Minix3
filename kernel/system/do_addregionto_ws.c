#include "kernel/system.h"
#include "kernel/arch/i386/include/arch_proto.h"
#include "kernel/arch/i386/hproto.h"
#include "kernel/arch/i386/htype.h"
#include <assert.h>
/*===============================================*
 *     do_addregionto_ws			 *
 *===============================================*/
int do_addregionto_ws(struct proc * caller,
   message * m_ptr){
  proc_nr_t proc_nr, proc_nr_e;
  struct proc *p;
  proc_nr_e = 
     (proc_nr_t) m_ptr->HADDREGIONTOWS_ENDPT;
  if (!isokendpt(proc_nr_e, &proc_nr)) 
     return(EINVAL);
  p = proc_addr(proc_nr);
  if(p->p_hflags & PROC_TO_HARD){
      add_region_to_ws(p, (u32_t *)p->p_seg.p_cr3 ,
            m_ptr->HADDREGIONTOWS_RADDR, 
            m_ptr->HADDREGIONTOWS_RLENGTH, 
            m_ptr->HADDREGIONTOWS_US1,
            m_ptr->HADDREGIONTOWS_US2);
  }
  return(OK);
}
