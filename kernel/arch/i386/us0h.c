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
static int update_ws_us1_us2_data_pmb(struct proc *rp,
   struct pram_mem_block *pmb);
int update_ws_us1_us2_data_vaddr(struct proc *rp, vir_bytes vaddr){
   int pde, pte;
   pde = I386_VM_PDE(vaddr); pte = I386_VM_PTE(vaddr);
   int r1, r2;
   struct pram_mem_block *pmb =  look_up_pte(rp, pde, pte);

   if(pmb->flags & H_EXEC){
      printf("EXEC?: update_ws_us1_us2_data: %d 0x%lx\n", rp->p_nr, vaddr);
      return(OK);
   }
   if(pmb && (pmb->us0!=MAP_NONE) && (pmb->us1!=MAP_NONE) &&
        (pmb->us2!=MAP_NONE)){
#if H_DEBUG
     r1 = cmp_frames(pmb->us0, pmb->us1);
     r2 = cmp_frames(pmb->us0, pmb->us2);
     if((r1!=OK) || (r2!=OK)){
        printf("update_ws_us1_us2_data: %d 0x%lx 0x%lx r1: %d r2: %d\n"
                 , rp->p_nr, vaddr, pmb->vaddr, r1, r2);
#endif
        if(cpy_frames(pmb->us0, pmb->us1)!=OK){
          printf("update_ws_us1_us2_data:Copy first_phys to pram failed\n");
          return(EFAULT);
        }
        if(cpy_frames(pmb->us0, pmb->us2)!=OK){
          printf("update_ws_us1_us2_data:Copy second_phys to pram failed\n");
          return(EFAULT);
        } 
        pmb->flags  |= IWS_MOD_KERNEL;
#if H_DEBUG
     }
#endif
   }  
#if H_DEBUG
   printf("NO?: update_ws_us1_us2_data: %d 0x%lx\n", rp->p_nr, vaddr);  
#endif 
   return(OK);
}

static int update_ws_us1_us2_data_pmb(struct proc *rp, struct pram_mem_block *pmb){
   if(!pmb) return(OK);
   int r1, r2;
   if((pmb->us0!=MAP_NONE) && (pmb->us1!=MAP_NONE) && 
       (pmb->us2!=MAP_NONE)){
#if H_DEBUG
     r1 = cmp_frames(pmb->us0, pmb->us1);
     r2 = cmp_frames(pmb->us0, pmb->us2);
     if((r1!=OK) || (r2!=OK)){
        printf("update_ws_us1_us2_data_pmb: %d 0x%lx r1: %d r2: %d\n"
           ,rp->p_nr, pmb->vaddr, r1, r2);
#endif
        if(cpy_frames(pmb->us0, pmb->us1)!=OK){
          printf("update_ws_us1_us2_data_pmb:Copy first_phys to pram failed\n");
          return(EFAULT);
       }
       if(cpy_frames(pmb->us0, pmb->us2)!=OK){
          printf("update_ws_us1_us2_data_pmb:Copy second_phys to pram failed\n");
          return(EFAULT);
       } 
#if H_DEBUG
    }
#endif
  }
#if H_DEBUG
   printf("NO? update_ws_us1_us2_data_pmb: %d 0x%lx\n", rp->p_nr, pmb->vaddr); 
#endif    
   return(OK);
}

int update_all_ws_us1_us2_data(struct proc *rp){
  if(rp->p_lus1_us2_size <= 0)
     return(OK);
  int r;
  struct pram_mem_block *pmb = rp->p_lus1_us2;
  while(pmb){
    if((r=update_ws_us1_us2_data_pmb(rp, pmb))!=OK)
        return(r);
    pmb = pmb->next_pmb;
  }
  return(OK);
}

int update_range_ws_us1_us2_data(struct proc *rp, vir_bytes offset,
             int n_pages_covered){
    int pde = I386_VM_PDE(offset);
    int pte = I386_VM_PTE(offset);
    vir_bytes page_base = pde * I386_VM_PT_ENTRIES * I386_PAGE_SIZE
                             + pte * I386_PAGE_SIZE;
    int i = 0;
    for(i = 0; i < n_pages_covered; i++ ){
#if H_DEBUG
       printf("vaddr_copy 0x%lx\n", page_base + i*4*1024);
#endif
       if(update_ws_us1_us2_data_vaddr(rp, page_base + i*4*1024)!=OK)
           return(EFAULT);
    }
    return(OK);
}

