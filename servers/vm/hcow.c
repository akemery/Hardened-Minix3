/*** Here the copy-on-write is implemented
 *** - The function vm_setpt_root_to_ro
 ***    modify the page table entries of the hardened 
 ***   process, All the USER accessed pages are set to NOT USER
 ***   Author: Emery Kouassi Assogba
 ***   Email: assogba.emery@gmail.com
 ***   Phone: 0022995222073
 ***   22/01/2019 lln***/

#include <machine/vm.h>

#include <minix/type.h>
#include <minix/syslib.h>
#include <minix/cpufeature.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <stdlib.h>


#include <machine/vm.h>

#include "htype.h"
#include "glo.h"
#include "proto.h"
#include "util.h"
#include "region.h"

static void free_pram_mem_block(struct vmproc *current_p, vir_bytes vaddr);

/*===========================================================================*
 *				get_pmb				             *
 *===========================================================================*/
struct pram_mem_block *get_pmb(void){
    /*   Return the first avalaible pmb in working_set table.
     **  If the table is full a panic is triggered 
     **  otherwise the found pmb is returnedtable */
    int pmb_offset = 0;
     /* start from the first pmb */
    struct pram_mem_block *pmb = BEG_PRAM_MEM_BLOCK_ADDR;
     /**If the first block is free return it**/ 
    if(pmb->flags & PRAM_SLOT_FREE) {
       /**Reset the data in the block and return the block**/
       pmb->flags &=~PRAM_SLOT_FREE;
       pmb->next_pmb = NULL;
       pmb->us1 = MAP_NONE;
       pmb->us2 = MAP_NONE;
       pmb->us0 = MAP_NONE;
       pmb->vaddr = MAP_NONE;
       return pmb;
    }
    do{
     /*** Otherwise go through the working_set and search the first available
      *** bloc  ***/
       pmb_offset++;
       pmb++;
    }while(!(pmb->flags & PRAM_SLOT_FREE) && pmb < END_PRAM_MEM_BLOCK_ADDR);

    /**The end of the working_set is reached panic **/
    if(pmb_offset>= WORKING_SET_SIZE)
       panic("Block list is full stop %d\n", pmb_offset);
    /**The bloc is found, reset the content of the bloc and return it**/
    pmb->flags &=~PRAM_SLOT_FREE;
    pmb->us1 = MAP_NONE;
    pmb->us2 = MAP_NONE;
    pmb->us0 = MAP_NONE;
    pmb->vaddr = MAP_NONE;
    pmb->next_pmb = NULL;
    return pmb;
}

/*===========================================================================*
 *				look_up_pte             	             *
 *===========================================================================*/
struct pram_mem_block * look_up_pte(struct vmproc *current_p, int pde, int pte){
    /** Search in the PE working set list the block with the given pde and pte
     ** if the working set list is empty a NULL pointer on block is return.
     ** If the end of
     ** the working set list is reached without finding the block a NULL
     ** pointer is return. If the block is found a pointer on the block is 
     ** return**/
    if(current_p->vm_first_step_workingset_id <= 0)
      return(NULL);
    struct pram_mem_block *pmb = current_p->vm_working_set;
    int __pte, __pde;
    while(pmb){
      __pte = I386_VM_PTE(pmb->vaddr);
      __pde = I386_VM_PDE(pmb->vaddr);
      if((__pte==pte)&&(__pde==pde))
	 return(pmb);
      pmb = pmb->next_pmb;
    }
    return(NULL);
}

/*===========================================================================*
 *				free_pram_mem_blocks           	             *
 *===========================================================================*/
void free_pram_mem_blocks(struct vmproc *current_p){
     /** Delete of the blokcs in the PE working set list. If the working 
      ** set list is empty the function return. Otherwise each blocks is delete
      ** A the end of the function the working set of the PE should be empty ***/
     if(current_p->vm_first_step_workingset_id <= 0)
          return;
     struct pram_mem_block *pmb = current_p->vm_working_set;
     while(pmb){
        free_pram_mem_block(current_p, pmb->vaddr);
	pmb = pmb->next_pmb;
     }
     assert(current_p->vm_first_step_workingset_id == 0);
     assert(current_p->vm_working_set == NULL);	
}

/*===============================================*
 *		free_pram_mem_block              *
 *===============================================*/

static void free_pram_mem_block(
     struct vmproc *current_p, vir_bytes vaddr){
  /* Delete the block corresponding to vaddr
   * from the PE woking set in
   * VM address space. If the block is found it is 
   * remove from the list
   * and the data structure in the whole available 
   * blocks is made free 
   * If the end of the list is reached the function 
   * return*/
   assert(current_p->vm_first_step_workingset_id > 0);
   struct pram_mem_block *pmb = 
                   current_p->vm_working_set; 
   struct pram_mem_block *prev_pmb = NULL;
   struct pram_mem_block *next_pmb = NULL;
   int __pte, __pde, pte, pde;
   pte = I386_VM_PTE(vaddr);
   pde = I386_VM_PDE(vaddr);
   while(pmb){
     __pte = I386_VM_PTE(pmb->vaddr);
     __pde = I386_VM_PDE(pmb->vaddr);
     if((__pte==pte)&&(__pde==pde)){
#if H_DEBUG
      printf("VM freeing %d: vaddr 0x%lx  pram 0x%lx "
        " first 0x%lx second: 0x%lx\n", 
         current_p->vm_endpoint, pmb->vaddr, pmb->us0, 
         pmb->us1, pmb->us2 );
#endif
      free_mem(ABS2CLICK(pmb->us1), 1);
      free_mem(ABS2CLICK(pmb->us2), 1);
      pmb->flags = PRAM_SLOT_FREE;
      pmb->vaddr = MAP_NONE;
      pmb->id    = 0; 
      pmb->us1 = MAP_NONE;
      pmb->us2 = MAP_NONE;
      pmb->us0 = MAP_NONE;
           current_p->vm_first_step_workingset_id--;
           if(prev_pmb)
              prev_pmb->next_pmb = pmb->next_pmb;
           else
             current_p->vm_working_set = pmb->next_pmb;
            break;
	}
	prev_pmb = pmb;
	next_pmb = pmb->next_pmb;
	pmb = pmb->next_pmb;
      }
}

/*===========================================================================*
 *				allocate_mem_4_hardening       	             *
 *===========================================================================*/
void allocate_mem_4_hardening (struct vmproc *vmp, 
          struct vir_region *region, struct phys_region *ph, int what ){
    /** When called allocate_mem_4_hardening allocate a frame for the hardening
     ** If it is called during the first run, the frame is allocated for US1
     ** If it is called during the second run, the frame is allocated for US2   
     ** The data in the corresponding frame in US0 is copied in the new frame
     ** The kernel is informed to update the bloc data structure within its own
     ** address space. **/
    struct pram_mem_block *pmb, *next_pmb;
    phys_bytes new_page_1, new_page_cl_1, phys_back;
    vir_bytes vaddr;
    u32_t allocflags;
    vaddr = region->vaddr+ph->offset;
    allocflags = vrallocflags(region->flags);

    vmp->vm_hflags |= VM_PROC_TO_HARD;
    if(!(pmb = look_up_pte(vmp,  I386_VM_PDE(vaddr),I386_VM_PTE(vaddr) ))){
    /* rememeber that we are working with page already in the working set*/
        pmb = get_pmb();
        assert(pmb);
#if CHECK_DEBUG
        assert(pmb->us0 ==  MAP_NONE);
        assert(pmb->us1 ==  MAP_NONE);
        assert(pmb->us2 ==  MAP_NONE);
        assert(pmb->vaddr ==  MAP_NONE);
#endif
        
         /** Here on frame is allocated ***/
        if((new_page_cl_1 = alloc_mem(1, allocflags|PAF_CLEAR)) == NO_MEM)
           panic("allocate_mem_4_hardening :"
               " no mem to allocate for copy-on-write\n");
        new_page_1 = CLICK2ABS(new_page_cl_1);

        /* copy the content of the current frame ram_phys in the new frame 
         * allocated */
        if(sys_abscopy(ph->ph->phys, new_page_1, VM_PAGE_SIZE) != OK) 
           panic("VM: abscopy failed: when copying data during copy"
                       " on write page fault handling\n");
        /* update the VM data structure *
         * linked the frames to us0, us1, 
         * us2 in the VM */
        pmb->us0 =  ph->ph->phys;
        if(what == VM_FIRST_RUN)
            pmb->us1 = new_page_1;
        if(what == VM_SECOND_RUN)
            pmb->us2 = new_page_1;
      
        pmb->vaddr     =   vaddr;

        /**Insert the new pmb bloc into the process's VM working set list**/
        if(!vmp->vm_first_step_workingset_id)
            vmp->vm_working_set = pmb;
        else{
             next_pmb = vmp->vm_working_set;
             while(next_pmb->next_pmb) next_pmb = next_pmb->next_pmb; 
             next_pmb->next_pmb = pmb;
             next_pmb->next_pmb->next_pmb = NULL;
        }
        pmb->id = vmp->vm_first_step_workingset_id;
        vmp->vm_first_step_workingset_id++; 
  
        /*** Now inform the Kernel so the VM will update it part of 
         *** pmb attributes : us0, us1, us2
         *** after sys_hmem_map the micro-kernel and the VM share the same
         *** information on the pmb attributes.***/
        if(what == VM_FIRST_RUN){
            if(sys_hmem_map(vmp->vm_endpoint, new_page_1,
                        -2L, -2L, 0)!=OK)
            panic("VM: sys_hmem_map failed: when informing the kernel during"
                     " copy on write page fault handling\n"); 
        }
        if(what == VM_SECOND_RUN){
            if(sys_hmem_map(vmp->vm_endpoint, -2L,
                        new_page_1, -2L, 0)!=OK)
            panic("VM: sys_hmem_map failed: when informing the kernel during"
                     " copy on write page fault handling\n"); 
        }
 
    }
    else{
        // TO COMPLETE
         if((pmb->us1 != MAP_NONE) &&
               (pmb->us2!=MAP_NONE)){
             pmb->us0 = ph->ph->phys;
              
        }

        if((pmb->us1 == MAP_NONE) ||
               (pmb->us2==MAP_NONE)){
            /** Here on frame is allocated ***/
           if((new_page_cl_1 = alloc_mem(1, allocflags|PAF_CLEAR)) == NO_MEM)
             panic("allocate_mem_4_hardening :"
               " no mem to allocate for copy-on-write\n");
           new_page_1 = CLICK2ABS(new_page_cl_1);
        }
        switch (what){
           case VM_FIRST_RUN: // TO COMPLETE
                 if(pmb->us1==MAP_NONE)
                    pmb->us1 = new_page_1;
                 /* copy the content of the current frame ram_phys in the new frame 
                  * allocated */
                 if(sys_abscopy(ph->ph->phys, pmb->us1, VM_PAGE_SIZE) != OK) 
                      panic("VM: abscopy failed: when copying data during copy"
                       " on write page fault handling\n");
                 if(sys_hmem_map(vmp->vm_endpoint, pmb->us1,
                        -2L, -2L, 0)!=OK)
                   panic("VM: sys_hmem_map failed: when informing the kernel during"
                     " copy on write page fault handling\n"); 
                 break;
           case VM_SECOND_RUN: // TO COMPLETE
                 if(pmb->us2==MAP_NONE)
                    pmb->us2 = new_page_1;
                 if(sys_abscopy(ph->ph->phys, pmb->us2, VM_PAGE_SIZE) != OK) 
                      panic("VM: abscopy failed: when copying data during copy"
                       " on write page fault handling\n");
                 if(sys_hmem_map(vmp->vm_endpoint, -2L,
                        pmb->us2, -2L, 0)!=OK)
                 panic("VM: sys_hmem_map failed: when informing the kernel during"
                     " copy on write page fault handling\n"); 
                 
                 break;
           default:
                panic("Unkown value for what in hmap_pf\n");
           
        }     
    }
    return;
}

struct pram_mem_block * add_pmb(struct vmproc *vmp, 
   vir_bytes v, phys_bytes pfa, 
   phys_bytes us1, phys_bytes us2){
  struct pram_mem_block *pmb, *next_pmb;
  /* ask for a new pmb block in the free list*/
  pmb = get_pmb(); 
  /* be sure that we got a good block*/
  assert(pmb); 
  pmb->us0 =  pfa;
  pmb->vaddr     =  v;
  pmb->us1 = us1;
  pmb->us2 = us2;
  /* Insert the block on the process's linked list*/
  if(!vmp->vm_first_step_workingset_id) 
     vmp->vm_working_set = pmb;
  else{
    next_pmb = vmp->vm_working_set;
    while(next_pmb->next_pmb) 
      next_pmb = next_pmb->next_pmb; 
    next_pmb->next_pmb = pmb;
    next_pmb->next_pmb->next_pmb = NULL;
  }
  pmb->id = vmp->vm_first_step_workingset_id;
  vmp->vm_first_step_workingset_id++;  
  return(pmb);
}

int free_region_pmbs(struct vmproc *vmp, 
      vir_bytes raddr, vir_bytes length){
   if(vmp->vm_first_step_workingset_id <= 0)
          return(OK);
   int p;
   int pde = I386_VM_PDE(raddr);
   int pte = I386_VM_PTE(raddr);
   vir_bytes page_base = 
         pde * ARCH_VM_PT_ENTRIES * VM_PAGE_SIZE
                            + pte * VM_PAGE_SIZE;
   vir_bytes vaddr;
   int n_pages_covered = (length + 
          (raddr - page_base) - 1)/(4*1024)  + 1;
   struct pram_mem_block *pmb ;
#if H_DEBUG
   printf("VM FREEPMBS %d\n", vmp->vm_endpoint);
#endif
   for(p = 0; p < n_pages_covered; p++){ 
       vaddr = page_base + p*4*1024;
       pde = I386_VM_PDE(vaddr);
       pte = I386_VM_PTE(vaddr);
       if(!(pmb =  look_up_pte(vmp, pde, pte)))
        continue;
       free_pram_mem_block(vmp, pmb->vaddr);
   }
   sys_free_pmbs(vmp->vm_endpoint, raddr, length );
   return(OK);
}


void do_hardening(message *m)
{
  endpoint_t ep = m->m_source;
  int reqtype = m->m_type;
  struct vmproc *vmp;
  int p;
  if(vm_isokendpt(ep, &p) != OK)
      panic("do_hardening: endpoint wrong: %d", ep);
  vmp = &vmproc[p];
  assert((vmp->vm_flags & VMF_INUSE));      
  switch(reqtype){
       case VM_TELL_VM_H_ENABLE:
          hardening_enabled = ENABLE_HARDENING;
          break;
     
     case VM_TELL_VM_H_DISABLE:
          hardening_enabled = DISABLE_HARDENING;
          break;
     case VM_TELL_VM_H_ENABLE_P:
          vmp->vm_hflags |= VM_PROC_TO_HARD;
          break;
     case VM_TELL_VM_H_DISABLE_P:
          vmp->vm_hflags &= ~VM_PROC_TO_HARD;
          break;
  }
}
