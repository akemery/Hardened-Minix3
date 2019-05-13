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
static void free_pram_mem_block(
     struct vmproc *current_p, vir_bytes vaddr);

int tell_kernel_for_us1_us2(struct vmproc *vmp, 
     vir_bytes v, phys_bytes physaddr, size_t bytes )
{
  int pages = bytes / VM_PAGE_SIZE, p;
  phys_bytes us1, us1_cl, us2, us2_cl;
  struct pram_mem_block *pmb;
  for(p = 0; p < pages; p++) {
    /*already in us1_us2 list?*/
    if(!(pmb = look_up_pte(vmp, 
       I386_VM_PDE(v),I386_VM_PTE(v) ))){ 
      /* no allocate us1 and us2 and add it to us1_us2
       * list */  
      if((us1_cl = alloc_mem(1, PAF_CLEAR)) == NO_MEM)
         panic("tell_kernel_for_us1_us2 :"
           " no mem to allocate for copy-on-write\n");
      us1 = CLICK2ABS(us1_cl);
      if((us2_cl = alloc_mem(1, PAF_CLEAR)) == NO_MEM)
         panic("tell_kernel_for_us1_us2 :"
            " no mem to allocate for copy-on-write\n");
      us2 = CLICK2ABS(us2_cl);
      pmb = add_pmb(vmp,  v, physaddr, us1, us2);
    }
    else pmb->us0 = physaddr;/*yes update US0*/
    if(sys_addregionto_ws(vmp->vm_endpoint, v, 1, 
       pmb->us1, pmb->us2)!=OK)
       return(EFAULT);
    v += VM_PAGE_SIZE;
    physaddr+=VM_PAGE_SIZE;
  }
  return(OK);
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
  if(!vmp->vm_lus1_us2_size) 
     vmp->vm_lus1_us2 = pmb;
  else{
    next_pmb = vmp->vm_lus1_us2;
    while(next_pmb->next_pmb) 
      next_pmb = next_pmb->next_pmb; 
    next_pmb->next_pmb = pmb;
    next_pmb->next_pmb->next_pmb = NULL;
  }
  pmb->id = vmp->vm_lus1_us2_size;
  vmp->vm_lus1_us2_size++;  
  return(pmb);
}

int free_region_pmbs(struct vmproc *vmp, 
      vir_bytes raddr, vir_bytes length){
   if(vmp->vm_lus1_us2_size <= 0)
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
   assert(current_p->vm_lus1_us2_size > 0);
   struct pram_mem_block *pmb = 
                   current_p->vm_lus1_us2; 
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
           current_p->vm_lus1_us2_size--;
           if(prev_pmb)
              prev_pmb->next_pmb = pmb->next_pmb;
           else
             current_p->vm_lus1_us2 = pmb->next_pmb;
            break;
	}
	prev_pmb = pmb;
	next_pmb = pmb->next_pmb;
	pmb = pmb->next_pmb;
      }
}


/*===========================================================================*
 *				get_pmb				             *
 *===========================================================================*/
struct pram_mem_block *get_pmb(void){
    /*   Return the first avalaible pmb in lus1_us2 table.
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
     /*** Otherwise go through the lus1_us2 and search the first available
      *** bloc  ***/
       pmb_offset++;
       pmb++;
    }while(!(pmb->flags & PRAM_SLOT_FREE) && pmb < END_PRAM_MEM_BLOCK_ADDR);

    /**The end of the lus1_us2 is reached panic **/
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
    if(current_p->vm_lus1_us2_size <= 0)
      return(NULL);
    struct pram_mem_block *pmb = current_p->vm_lus1_us2;
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
     if(current_p->vm_lus1_us2_size <= 0)
          return;
     struct pram_mem_block *pmb = current_p->vm_lus1_us2;
     while(pmb){
        free_pram_mem_block(current_p, pmb->vaddr);
	pmb = pmb->next_pmb;
     }
     assert(current_p->vm_lus1_us2_size == 0);
     assert(current_p->vm_lus1_us2 == NULL);	
}
