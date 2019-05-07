#include "kernel/system.h"
#include "kernel/arch/i386/include/arch_proto.h"
#include "kernel/arch/i386/hproto.h"
#include "kernel/arch/i386/htype.h"
#include <assert.h>
/*=============================================*
 *	     do_free_pmbs	               *
 *=============================================*/
int do_free_pmbs(struct proc * caller, message * m_ptr)
{
  proc_nr_t proc_nr, proc_nr_e;
  struct proc *p;
  proc_nr_e= (proc_nr_t) m_ptr->FREE_PMBS_ENDPT;
  if (!isokendpt(proc_nr_e, &proc_nr)) return(EINVAL);
  p = proc_addr(proc_nr);
  if(p->p_hflags & PROC_TO_HARD){
     free_pram_mem_block_vaddr(p, 
           m_ptr->FREE_PMBS_REGION_ADDR, 
           m_ptr->FREE_PMBS_REGION_LEN);        
  }
  return(OK);
}
