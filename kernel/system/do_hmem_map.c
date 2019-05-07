

#include "kernel/system.h"
#include "kernel/arch/i386/include/arch_proto.h"
#include "kernel/arch/i386/hproto.h"
#include "kernel/arch/i386/htype.h"
#include <assert.h>



/*===========================================================================*
 *			          do_hmem_map				     *
 *===========================================================================*/
int do_hmem_map(struct proc * caller, message * m_ptr)
{
  

  proc_nr_t proc_nr, proc_nr_e;
  struct proc *p;

  proc_nr_e= (proc_nr_t) m_ptr->HMEM_MAP_ENDPT;

  if (!isokendpt(proc_nr_e, &proc_nr)) return(EINVAL);
  
  p = proc_addr(proc_nr);

  if(m_ptr->HMEM_MAP_PRAM2_ADDR == -10L){
    printf("Got shared region att %d 0x%lx 0x%lx\n", p->p_nr,
     m_ptr->HMEM_MAP_FIRST_ADDR, m_ptr->HMEM_MAP_SECOND_ADDR);
    if(p->p_hflags & PROC_TO_HARD){
       add_hsr(p, m_ptr->HMEM_MAP_FIRST_ADDR, 
         m_ptr->HMEM_MAP_SECOND_ADDR,m_ptr->HMEM_R_ID);
       p->p_hflags |= PROC_SHARING_MEM;
    }
    return(OK);
  }

  if((m_ptr->HMEM_MAP_PRAM2_ADDR == -0L) && 
            (m_ptr->HMEM_MAP_SECOND_ADDR == -0L)){
     printf("Can enable hardening\n");
     h_can_start_hardening = 1;
     return(OK);

  }
 
  struct pram_mem_block * pmb = look_up_lastpf_pte(p, 0);
  if(!pmb)
     panic("pmb is NULL, should not happen\n");
  u32_t pde_v, *pte_a, pte_v;
  int pde = I386_VM_PDE(pmb->vaddr);
  int pte = I386_VM_PTE(pmb->vaddr);
  pde_v = phys_get32((u32_t) ((u32_t *)p->p_seg.p_cr3 + pde));
  pte_a = (u32_t *) I386_VM_PFA(pde_v);
  pte_v = phys_get32((u32_t) (pte_a + pte));

  if((m_ptr->HMEM_MAP_PRAM2_ADDR == -2L) && 
            (m_ptr->HMEM_MAP_SECOND_ADDR == -2L)){
    pmb->us1  = m_ptr->HMEM_MAP_FIRST_ADDR;
    pte_v = (pte_v & I386_VM_ADDR_MASK_INV) |  
                      I386_VM_WRITE | pmb->us1;
  }
  if((m_ptr->HMEM_MAP_PRAM2_ADDR == -2L) && 
              (m_ptr->HMEM_MAP_FIRST_ADDR == -2L)){
    pmb->us2 = m_ptr->HMEM_MAP_SECOND_ADDR;
    pte_v = (pte_v & I386_VM_ADDR_MASK_INV) | 
                     I386_VM_WRITE | pmb->us2;
  }
  phys_set32((u32_t) (pte_a + pte), &pte_v);
  return(OK);
}


