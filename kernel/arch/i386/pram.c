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

static int 
 look_up_unique_pte(struct proc *current_p, 
     int pde, int pte);
static struct pram_mem_block * add_pmb(struct proc *p,
      phys_bytes pfa, 
      vir_bytes v, int pte);
static int check_pt_entry(u32_t pte_v);
static struct pram_mem_block * 
   add_pmb_vaddr(struct proc *p, phys_bytes pfa, 
   vir_bytes vaddr, phys_bytes us1, phys_bytes us2);
static void vm_setpt_to_ro(struct proc *p,
   u32_t *pagetable, const u32_t v);
/*============================================*
 *		check_vaddr_2                 *
 *============================================*/

int check_vaddr_2(struct proc *p, 
    u32_t *root, vir_bytes vaddr, int *rw){
/* A page fault occured. That function 
 * check if the virtual addresse match 
 * with a page entry whose access was 
 * restricted by the  hardened code. 
 * If it is the case, the access is allowed 
 * and  the VM is not called when 
 * the corresponding frame in US1 and US2 exist. 
 * Otherwise the VM is called to
 * allocate the frame for US1 or US2
 * if the virtual address does not match any
 * page in the current working set 
 * that will end the PE. the VM will be called
 * to handle the  normal page fault 
 * When the corresponding frames in
 * US1 and US2 exist, the pmb is labelled to
 * remember that a page fault was occured in that 
 * page. That is used at the 
 * beginning of the fisrt or the second run to 
 * set these page to read-write.
 * The addresses where the page fault occured is 
 * store for the first and the s
 * second run. That is used during the comparison step.
 **/
   int pde, pte;
   u32_t pde_v, *pte_a, pte_v;
   int nblocks;
   static int cnpf = 0;
   struct pram_mem_block *pmb, *next_pmb;
   assert((h_step == FIRST_RUN) || 
        (h_step == SECOND_RUN) || 
        (h_step == FIRST_STEPPING));
   /* read the pde entry and the 
    * pte entry of the PF page */
   pde = I386_VM_PDE(vaddr);
   pte = I386_VM_PTE(vaddr);
   if(h_step == FIRST_RUN)
      pagefault_addr_1 = vaddr;
   if(h_step == SECOND_RUN)
      pagefault_addr_2 = vaddr;
   /* read the page directory entry value of 
    *the page table related to the virtual
    * address */
   pde_v = phys_get32((u32_t) (root + pde));
   /* check if the pde entry is present ,
    * writable, not user, global
    * bigpage . Let the VM handle */
   if(check_pt_entry(pde_v)!=OK) 
       return(VM_HANDLED_NO_ACESS);
   /**read the page table address**/
   pte_a = (u32_t *) I386_VM_PFA(pde_v);
   /* read the page table entry value */
   pte_v = phys_get32((u32_t) (pte_a + pte));
   /* check the presence. If not present,
    * let the VM handle it*/
   if(!(pte_v & I386_VM_PRESENT))  
       return(VM_HANDLED_NO_PRESENT);
   /* be sure that it is a modified page table entry 
    * otherwise let the VM handle it*/
   /* read the current frame value*/
   u32_t pfa = I386_VM_PFA(pte_v);
   /* check if the page  is already in 
    * the working set*/
   if(!(pmb = look_up_pte(p, pde, pte))){
      /* remember we are working with a page 
       * already in the working set*/
      /* the page is not in the working, 
       * that should never happen */
#if H_DEBUG
      printf("a page fault occur outside the "
             "initiale working set"
           "%d %d 0x%lx\n", h_proc_nr, h_step, vaddr);
#endif
      return(VM_HANDLED_PF_ABS_WS);
   }      
#if CHECK_DEBUG
   /* be sure we have a valid data structure */
   assert(pmb); 
   /* be sure we have a valid virtual address
    * and a valid ram_phys*/
   assert(pmb->us0!=MAP_NONE);
   assert(pmb->us0 == pfa);
   assert(pmb->vaddr!=MAP_NONE);
#endif
   if((pmb->us1!=MAP_NONE) && 
      (pmb->us2!=MAP_NONE)){
#if H_DEBUG
      printf("a page fault handled by the kernel"
           "%d %d 0x%lx\n", h_proc_nr, h_step, vaddr);
#endif
      if(h_step == FIRST_RUN){
         if(pmb->flags & H_FORK)
             return(VM_HANDLED_PF_ABS_WS);
         pte_v = (pte_v & I386_VM_ADDR_MASK_INV) |  
              I386_VM_WRITE | pmb->us1;
         pmb->flags |= IWS_PF_FIRST;
      }
      else  if(h_step == SECOND_RUN){
          if(pmb->flags & H_FORK)
             return(VM_HANDLED_PF_ABS_WS);
         pte_v = (pte_v & I386_VM_ADDR_MASK_INV) |  
              I386_VM_WRITE | pmb->us2;
         pmb->flags |= IWS_PF_SECOND; 
      }
      phys_set32((u32_t) (pte_a + pte), &pte_v);
      *rw = K_HANDLE_PF;
      pmb->flags |= HGET_PF; 
      return(OK);
   }else if(h_step == FIRST_RUN){
       /* VM_HR1PAGEFAULT: 
        * Tell the VM it is a Read-Only page*/   
          *rw = RO_PAGE_FIRST_RUN;
          pmb->flags |= IWS_PF_FIRST; 
      }  
   else if(h_step == SECOND_RUN) {
#if CHECK_DEBUG
       assert(pmb->us0!=MAP_NONE);
       assert(pmb->us1!=MAP_NONE);
       assert(pmb->us2!=MAP_NONE);
#endif  
      *rw = RO_PAGE_SECOND_RUN;
      pmb->flags |= IWS_PF_SECOND; 
    } 
    
   /*It is the first page fault on 
    * that page. Tell the VM to allocate 3 new 
    * frames pram2_phys, us1 and us2 */
   pmb->flags |= PRAM_LAST_PF;
   pmb->flags |= HGET_PF;         
   /* be sure that the page is not insert
    * more than once in the working set*/
   nblocks = look_up_unique_pte(p, 
     I386_VM_PDE(vaddr),I386_VM_PTE(vaddr) );
   assert(nblocks <= 1);
   return(OK);
}

/*==========================================*
 *		look_up_pte                 *
 *==========================================*/
struct pram_mem_block * look_up_pte(
      struct proc *current_p, int pde, int pte){
   if(current_p->p_lus1_us2_size > 0){
      struct pram_mem_block *pmb = 
           current_p->p_lus1_us2;
      int __pte, __pde;
      while(pmb){
         __pte = I386_VM_PTE(pmb->vaddr);
         __pde = I386_VM_PDE(pmb->vaddr);
         if((__pte==pte)&&(__pde==pde))
	   return(pmb);
         pmb = pmb->next_pmb;
      }
   }
   return(NULL);
}

/*===============================================*
 *	    look_up_unique_pte                   *
 *===============================================*/
static int look_up_unique_pte(
   struct proc *current_p, int pde, int pte){
  int npte;
  if(current_p->p_lus1_us2_size > 0){
     struct pram_mem_block *pmb = current_p->p_lus1_us2;
     int __pte, __pde;
     npte = 0;
     while(pmb){
       __pte = I386_VM_PTE(pmb->vaddr);
       __pde = I386_VM_PDE(pmb->vaddr);
       if((__pte==pte)&&(__pde==pde))
	 npte++;
        pmb = pmb->next_pmb;
     }
   }
   return(npte);
}

/*====================================================*
 *				look_up_lastpf_pte    *
 *====================================================*/
struct pram_mem_block * 
 look_up_lastpf_pte(struct proc *current_p, int normal){
	if(current_p->p_lus1_us2_size > 0){
		struct pram_mem_block *pmb =
                    current_p->p_lus1_us2;
		while(pmb){

		  if(pmb->flags & PRAM_LAST_PF){
                          pmb->flags &= ~PRAM_LAST_PF;
		          return(pmb);
                      }
		  pmb = pmb->next_pmb;
		}
	}
	return(NULL);
}

/*===================================================*
 *				free_pram_mem_blocks *
 *===================================================*/
void free_pram_mem_blocks(struct proc *current_p,
          int no_msg_to_vm){
     /** Delete of the blokcs in the PE working 
      *  set list. If the working 
      ** set list is empty the function return. 
      *  Otherwise each blocks is delete
      ** A the end of the function the working set 
      *  of the PE should be empty ***/
     if(current_p->p_lus1_us2_size <= 0)
          return;
     struct pram_mem_block *pmb = current_p->p_lus1_us2;
     while(pmb){
        if((pmb->flags & H_TO_UPDATE) && 
               (no_msg_to_vm == FROM_EXEC)){
           pmb = pmb->next_pmb;
           continue;
        }
        free_pram_mem_block(current_p, 
              pmb->vaddr, (u32_t *)current_p->p_seg.p_cr3);
	pmb = pmb->next_pmb;
     }
     if(no_msg_to_vm != FROM_EXEC){
        assert(current_p->p_lus1_us2_size == 0);
        assert(current_p->p_lus1_us2 == NULL);	
     }
}

/*==============================================*
 *		free_pram_mem_blocks            *
 *==============================================*/
void free_pram_mem_block_vaddr(struct proc *rp,
     vir_bytes raddr, int len){
   if(rp->p_lus1_us2_size <= 0)
     return;
   int p;
   int pde = I386_VM_PDE(raddr);
   int pte = I386_VM_PTE(raddr);
   vir_bytes page_base = 
          pde * I386_VM_PT_ENTRIES * I386_PAGE_SIZE
                            + pte * I386_PAGE_SIZE;
   vir_bytes vaddr;
   int n_pages_covered = (len + 
        (raddr - page_base) - 1)/(4*1024)  + 1;
   struct pram_mem_block *pmb ;
#if H_DEBUG
     printf("KERNEL FREEPMBS %d %d 0x%lx %d\n", rp->p_endpoint,
        n_pages_covered, raddr, len);
#endif
   for(p = 0; p < n_pages_covered; p++){ 
     vaddr = page_base + p*4*1024;
     pde = I386_VM_PDE(vaddr);
     pte = I386_VM_PTE(vaddr);
     if(!(pmb =  look_up_pte(rp, pde, pte)))
         continue;
     free_pram_mem_block(rp, 
              pmb->vaddr, (u32_t *)rp->p_seg.p_cr3);
    }
}

/*==============================================*
 *		free_pram_mem_block           	*
 *==============================================*/
void free_pram_mem_block(struct proc *current_p,
    vir_bytes vaddr, u32_t *root){
   /* Delete the block corresponding to vaddr 
    * from the PE woking set in
    * VM address space. If the block is found 
    * it is remove from the list
    * and the data structure in the whole 
    * available blocks is made free 
    * If the end of the list is reached 
    * the function return **/
   if(current_p->p_lus1_us2_size <= 0)
      return;
   struct pram_mem_block *pmb = 
            current_p->p_lus1_us2; 
   struct pram_mem_block *prev_pmb = NULL;
   struct pram_mem_block *next_pmb = NULL;
   int __pte, __pde, pte, pde;
   u32_t pde_v, *pte_a, pte_v;
   pte = I386_VM_PTE(vaddr);
   pde = I386_VM_PDE(vaddr);
   while(pmb){
     __pte = I386_VM_PTE(pmb->vaddr);
     __pde = I386_VM_PDE(pmb->vaddr);
     if((__pte==pte)&&(__pde==pde)){
        pde_v = phys_get32((u32_t) (root + pde));
#if H_DEBUG
        printf("KERNEL freeing %d: vaddr 0x%lx  "
             "pram 0x%lx first 0x%lx second: 0x%lx\n", 
          current_p->p_endpoint, pmb->vaddr, pmb->us0, 
            pmb->us1, pmb->us2 );
#endif

#if CHECK_DEBUG
        assert((pde_v & I386_VM_PRESENT));
        assert((pde_v & I386_VM_WRITE));
        assert((pde_v & I386_VM_USER));
        assert(!(pde_v & I386_VM_GLOBAL));
        assert(!(pde_v & I386_VM_BIGPAGE));
        pte_a = (u32_t *) I386_VM_PFA(pde_v);
        pte_v = phys_get32((u32_t) (pte_a + pte));
        assert((pte_v & I386_VM_PRESENT));
#endif
        pmb->flags = PRAM_SLOT_FREE;
        pmb->vaddr = MAP_NONE;
        pmb->id    = 0; 
        pmb->us0 = MAP_NONE;
        pmb->us1 = MAP_NONE;
        pmb->us2 = MAP_NONE;
        current_p->p_lus1_us2_size--;
        if(prev_pmb)
          prev_pmb->next_pmb = pmb->next_pmb;
        else
          current_p->p_lus1_us2 = pmb->next_pmb;
        break;
     }
     prev_pmb = pmb;
     next_pmb = pmb->next_pmb;
     pmb = pmb->next_pmb;
  }
}


/*=============================================*
 *				vm_reset_pram  *
 *=============================================*/

void vm_reset_pram(struct proc *p, 
    u32_t *root, int endcmp){
   /* This function is called at the end of 
    * the PE, first or second run
    * It restore the PE memory space to US0
    * It copy the content of each frame 
    * from the second (US0) run to 
    * the corresponding frame in the US0 when 
    * the comparison succeeded
    *
    */
   assert(p->p_nr != VM_PROC_NR);
   if(p->p_lus1_us2_size <= 0)
      return;
   struct pram_mem_block *pmb = p->p_lus1_us2;
      /** Go through the working set list**/
   while(pmb){
#if CHECK_DEBUG
      assert(pmb->us0!=MAP_NONE);
      assert(pmb->us1!=MAP_NONE);
      assert(pmb->us2!=MAP_NONE);
      if((pmb->us0 == MAP_NONE) ||
          (pmb->us1 == MAP_NONE) ||
         (pmb->us2 == MAP_NONE)){
         pmb = pmb->next_pmb;
         continue;
    }
#endif 
   /** Yes a page fault occu get the pte and the pde**/
   int pde, pte;
   u32_t pde_v, *pte_a, pte_v;
   pde = I386_VM_PDE(pmb->vaddr);
   pte = I386_VM_PTE(pmb->vaddr);
   /** Read the page directory value entry**/
   pde_v = phys_get32((u32_t) (root + pde));
#if CHECK_DEBUG
   /**Check PRESENT, WRITE, USER, GLOBAL and BIGPAGE**/
   assert((pde_v & I386_VM_PRESENT));
   assert((pde_v & I386_VM_WRITE));
   assert((pde_v & I386_VM_USER));
   assert(!(pde_v & I386_VM_GLOBAL));
   assert(!(pde_v & I386_VM_BIGPAGE));
#endif
    /** Read the page table addresse**/
   pte_a = (u32_t *) I386_VM_PFA(pde_v);
   /** Read the page table entry value**/
   pte_v = phys_get32((u32_t) (pte_a + pte));
#if CHECK_DEBUG
   /** Verify the PRESENCE**/
   assert((pte_v & I386_VM_PRESENT));
#endif
   /** Read the frame address**/
   u32_t pfa = I386_VM_PFA(pte_v);

   if(endcmp == ABORT_PE){
       pmb->flags &= ~IWS_PF_SECOND;  
       pmb->flags &= ~IWS_PF_FIRST;
       pmb->flags &= ~HGET_PF;
       pmb->flags &= ~IWS_MOD_KERNEL;
       if(((pmb->us1!=MAP_NONE) || 
            (pmb->us2!=MAP_NONE)) &&
            (pmb->us0!=MAP_NONE)){
        if(pmb->us1!=MAP_NONE){
           if(cpy_frames(pmb->us0, pmb->us1)!=OK)
               panic("Copy second_phys to"
                           " us0 failed\n"); 
        }
        if(pmb->us2!=MAP_NONE){
           if(cpy_frames(pmb->us0, pmb->us2)!=OK)
                panic("Copy second_phys"
                       " to us0 failed\n"); 
         }
         pte_v = 
             (pte_v & I386_VM_ADDR_MASK_INV) | 
                        I386_VM_WRITE | pmb->us0;
         if(phys_set32((u32_t) (pte_a + pte), 
                     &pte_v)!=OK)
                 panic("Updating page table from "
                      "second_phy to us0" "failed\n");
      }
      pmb = pmb->next_pmb;
      continue;
   }

   if((h_step == FIRST_RUN) && 
       (endcmp == CPY_RAM_FIRST)){
      /** That is the end of the first 
       *  run let's map the page to PRAM as
       ** RW so before the starting of the PE
       *  the page will be set RO
       ** During the second RUN the PE will make 
       * the same page fault
       **/
      if(!(pte_v & I386_VM_DIRTY) && 
            (pmb->flags & IWS_PF_FIRST)){
             pmb->flags &= ~IWS_PF_FIRST;
#if H_DEBUG
             printf("NO FIRST DIRTY BIT MODIFIED"
                " 0x%lx pram 0x%lx " 
                     "first 0x%lx second 0x%lx\n", 
             pmb->vaddr, pmb->us0, 
             pmb->us1, pmb->us2);
#endif
      }

#if H_DEBUG
      if(pmb->flags & WS_SHARED){
              printf("FIRST SHARED PAGE 0x%lx"
              " pram 0x%lx " 
                     "first 0x%lx second 0x%lx\n", 
               pmb->vaddr, pmb->us0, 
               pmb->us1, pmb->us2);
      }
#endif

      if((pmb->us1!=MAP_NONE) && 
           (pmb->us0 !=MAP_NONE) &&
           ((pmb->flags & HGET_PF)
           || (pte_v & I386_VM_DIRTY))){

#if H_DEBUG
          if(!(pmb->flags & HGET_PF) && 
                (pte_v & I386_VM_DIRTY))
            printf("FIRST DIRTY BIT MODIFIED 0x%lx"
                " pram 0x%lx " 
                     "first 0x%lx second 0x%lx\n", 
                 pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2);
#endif
       if((pmb->flags & IWS_MOD_KERNEL) && 
                 (pte_v & I386_VM_DIRTY) )
                    pmb->flags |= IWS_PF_FIRST;
       pte_v &= ~I386_VM_DIRTY;
       if(phys_set32((u32_t) (pte_a + pte), 
                &pte_v)!=OK)
            panic("Updating page table"
                " from second_phy to us0"
                          "failed\n");
       pmb->flags &= ~HGET_PF;
       pmb->flags |= FWS;
    }
     
#if H_DEBUG
       if(pmb->flags & IWS_MOD_KERNEL)
            printf("FIRST MODIFIED BY KERNEL "
                 "0x%lx pram 0x%lx " 
                     "first 0x%lx second 0x%lx\n",
                 pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2);
#endif
                      
   }
   if(h_step == SECOND_RUN) {
      switch(endcmp){
         case CPY_RAM_PRAM:
            /* The comparison succed let's 
             * copy the content of 
             * us2 to us0 and map the page to us0
             * Before the starting of the PE all
             * writable pages are set to
             * RO so we have to put now the page 
             * as RW thus it will be
             * put to RO before starting the PE. 
             * Otherwise it will be
             * ignored **/
             if(!(pte_v & I386_VM_DIRTY) && 
                (pmb->flags & IWS_PF_SECOND)){
                 pmb->flags &= ~IWS_PF_SECOND;
#if H_DEBUG
                 printf("NO SECOND DIRTY BIT MODIFIED"
                   " 0x%lx pram 0x%lx " 
                     "first 0x%lx second 0x%lx\n", 
                  pmb->vaddr, pmb->us0, 
                  pmb->us1, pmb->us2);
#endif
             }
#if H_DEBUG
             if(pmb->flags & WS_SHARED){
                 printf("SECOND SHARED PAGE "
                     "0x%lx pram 0x%lx " 
                     "first 0x%lx second 0x%lx\n", 
                 pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2);
             }
#endif

             if((pmb->us2!=MAP_NONE) &&
                 (pmb->us0!=MAP_NONE) &&  
               ((pmb->flags & HGET_PF)
                    || (pte_v & I386_VM_DIRTY))){
#if H_DEBUG
                if(!(pmb->flags & HGET_PF) && 
                    (pte_v & I386_VM_DIRTY))
                    printf("SECOND DIRTY BIT "
                     "MODIFIED 0x%lx pram 0x%lx " 
                     "first 0x%lx second 0x%lx\n", 
                  pmb->vaddr, pmb->us0, 
                  pmb->us1, pmb->us2);
#endif

                if((pmb->flags & IWS_MOD_KERNEL) && 
                     (pte_v & I386_VM_DIRTY) )
                    pmb->flags |= IWS_PF_SECOND;
                
                if(cpy_frames(pmb->us2, 
                     pmb->us0)!=OK)
                   panic("Copy second_phys to us0 "
                        "failed\n"); 
                if(pmb->flags & WS_SHARED)
                   enable_hme_event_in_procs(p, 
                   pmb->vaddr, I386_PAGE_SIZE );
                pmb->flags &= ~HGET_PF;
                pte_v &= ~I386_VM_DIRTY;
             }

             pte_v = (pte_v & I386_VM_ADDR_MASK_INV) | 
                        I386_VM_WRITE | pmb->us0;
             if(phys_set32((u32_t) (pte_a + pte), 
                &pte_v)!=OK)
                panic("Updating page table from" 
                   "second_phy to us0 failed\n");

             if(pmb->flags & IWS_MOD_KERNEL){
                 pmb->flags &= ~IWS_MOD_KERNEL;
#if H_DEBUG
                 printf("SECOND MODIFIED BY KERNEL"
                     " 0x%lx pram 0x%lx " 
                     "first 0x%lx second 0x%lx\n", 
                 pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2);
#endif
             }
             break;
          case CMP_FAILED:
             /** The comparison failed let's
              ** copy map the page to PRAM 
              ** and set it to RW. Thus before
              ** the starting of the PE
              ** the page will be set to RO. 
              ** The PE state is restored
              ** to US0
              */ 
  
             pmb->flags &= ~IWS_PF_SECOND;  
             pmb->flags &= ~IWS_PF_FIRST;
             pmb->flags &= ~HGET_PF;
             pmb->flags &= ~IWS_MOD_KERNEL;

             if(((pmb->us1!=MAP_NONE) || 
                (pmb->us2!=MAP_NONE)) &&
                 (pmb->us0!=MAP_NONE)){
               if(pmb->us1!=MAP_NONE){
                 if(cpy_frames(pmb->us0, pmb->us1)!=OK)
                    panic("Copy second_phys to"
                           " us0 failed\n"); 
                }
                if(pmb->us2!=MAP_NONE){
                if(cpy_frames(pmb->us0, pmb->us2)!=OK)
                       panic("Copy second_phys"
                          " to us0 failed\n"); 
                }

                pte_v = 
                   (pte_v & I386_VM_ADDR_MASK_INV) | 
                        I386_VM_WRITE | pmb->us0;
                if(phys_set32((u32_t) (pte_a + pte), 
                     &pte_v)!=OK)
                 panic("Updating page table from "
                      "second_phy to us0" "failed\n");
             }
             break;
          case CPY_RAM_FIRST_STEPPING :
             if(pmb->us1!=MAP_NONE){
               if(pmb->flags & IWS_PF_FIRST)
                  pte_v = (pte_v & I386_VM_ADDR_MASK_INV) | 
                        I386_VM_WRITE | pmb->us1;
               else
                  pte_v = (pte_v & I386_VM_ADDR_MASK_INV) | pmb->us1;
               if(phys_set32((u32_t) (pte_a + pte), &pte_v)!=OK)
                    panic("Updating page table from second_phy to pram_phys"
                          "failed\n");
             }
             break;
          default :
             /**TO COMPLETE**/
             panic("Should never happen");
             break;
       }             
     }
    pmb = pmb->next_pmb;
  }
  refresh_tlb();
}


static struct pram_mem_block * add_pmb(struct proc *p, 
      phys_bytes pfa, 
      vir_bytes v, int pte){
  struct pram_mem_block *pmb, *next_pmb;
  /* ask for a new pmb block in the free list*/
  pmb = get_pmb();
  /* be sure that we got a good block*/ 
  assert(pmb); 
  pmb->us0 =  pfa;
  pmb->vaddr     =  v + pte * I386_PAGE_SIZE;
  if(!pfa) pmb->flags |= H_HAS_NULL_PRAM;
  /* Insert the block on the process's linked list*/
  if(!p->p_lus1_us2_size) p->p_lus1_us2 = pmb;
  else{
    next_pmb = p->p_lus1_us2;
    while(next_pmb->next_pmb) next_pmb = next_pmb->next_pmb; 
    next_pmb->next_pmb = pmb;
    next_pmb->next_pmb->next_pmb = NULL;
  }
  pmb->id = p->p_lus1_us2_size;
  p->p_lus1_us2_size++;  
  return(pmb);
}

static int check_pt_entry(u32_t pte_v){
   /* check if the page is present*/
   if(!(pte_v & I386_VM_PRESENT)) 
      return(VM_HANDLED_NO_PRESENT);
   /* Check if it is a NON USER PAGE*/
   if(!(pte_v & I386_VM_USER)) 
      return(VM_HANDLED_NO_ACESS); 
   /* Check if it is a GLOBAL_PAGE 
    *(buffer shared between os and process)*/
   if((pte_v & I386_VM_GLOBAL)) 
      return( VM_HANDLED_GLOBAL); 
   /* Check if it is a NON BIG_PAGE
   ( BIGPAGES are not implemented in Minix)*/
   if((pte_v & I386_VM_BIGPAGE)) 
      return(VM_HANDLED_BIG); 
   /* Check if it is a WRITE*/
   if(!(pte_v & I386_VM_WRITE)) 
      return(VM_HANDLED_NO_ACESS);
   return(OK); 
}

/*==========================================*
 *				display_mem *
 *==========================================*/
void display_mem(struct proc *current_p){
   if(current_p->p_lus1_us2_size > 0){
	struct pram_mem_block *pmb = 
            current_p->p_lus1_us2;
	while(pmb){
          if(pmb->us0!=MAP_NONE)
	  printf("displaying vaddr 0x%lx  "
            "pram 0x%lx first 0x%lx second: 0x%lx\n", 
                 pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2);
			pmb = pmb->next_pmb;
	}
    }
}

/*===========================================================================*
 *				get_pmb				             *
 *===========================================================================*/
/*   Return the first avalaible pmb in lus1_us2 table.
 **  If the table is full a panic is triggered 
 **  otherwise the found pmb is returnedtable */
struct pram_mem_block *get_pmb(void){
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
	   panic("ALERT BLOCK LIST IS FULL STOP STOP %d\n", pmb_offset);

        /**The bloc is found, reset the content of the bloc and return it**/
	pmb->flags &=~PRAM_SLOT_FREE;
        pmb->us1 = MAP_NONE;
        pmb->us2 = MAP_NONE;
        pmb->us0 = MAP_NONE;
        pmb->vaddr = MAP_NONE;
        pmb->next_pmb = NULL;
	return pmb;
}

int add_region_to_ws(struct proc *p, u32_t *root,
          vir_bytes r_base_addr, 
          int length, phys_bytes us1, 
          phys_bytes us2){
   u32_t pde_v, pte_v; // pde entry value
   u32_t *pte_a; // page table address
   u32_t pfa;
   int i;
   int pde = I386_VM_PDE(r_base_addr);
   int pte = I386_VM_PTE(r_base_addr);
   vir_bytes page_base = 
        pde * I386_VM_PT_ENTRIES * I386_PAGE_SIZE
                            + pte * I386_PAGE_SIZE;
   vir_bytes vaddr;
   int n_pages_covered = 
      (length + 
      (r_base_addr - page_base) - 1)/(4*1024)  + 1;
   for(i = 0; i < n_pages_covered; i++ ){
#if H_DEBUG
     printf("vaddr in region 0x%lx\n", 
         page_base + i*4*1024);
#endif
     vaddr = page_base + i*4*1024;
     pde = I386_VM_PDE(vaddr);
     pte = I386_VM_PTE(vaddr);
     pde_v = phys_get32((u32_t) (root + pde));
     /*read the page table address*/
     pte_a = (u32_t *) I386_VM_PFA(pde_v);
     /* read the page table entry value*/
     pte_v = phys_get32((u32_t) (pte_a + pte)); 
     /* read the frame address value*/
     pfa = I386_VM_PFA(pte_v);
     struct pram_mem_block *pmb;  
      if(!(pmb = look_up_pte(p, I386_VM_PDE(vaddr), 
          I386_VM_PTE(vaddr) )))
         pmb = add_pmb_vaddr(p, pfa, vaddr,us1,us2); 
      else 
         pmb->us0 = pfa;
      if(pmb->flags & H_FORK){
          pmb->flags = pmb->iflags;
          pmb->flags &= ~H_FORK;
      }

        if(pmb->flags & H_EXEC){
          pmb->flags = pmb->iflags;
          pmb->flags &= ~H_EXEC;
          printf("EXEC  %d vaddr 0x%lx  "
            "pram 0x%lx first 0x%lx second: 0x%lx %d\n", 
                 p->p_nr, pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2, pmb->flags);
      }
      pmb->flags |= H_TO_UPDATE;
      
       
    }
#if H_DEBUG__
    printf("### start adding ### \n");
    display_mem(p);
    printf("### end adding ###\n");
#endif
    return(OK); 
}

static struct pram_mem_block * add_pmb_vaddr(
      struct proc *p,
      phys_bytes pfa, vir_bytes vaddr, 
      phys_bytes us1, phys_bytes us2){
  struct pram_mem_block *pmb, *next_pmb;
  /* ask for a new pmb block in the free list*/
  pmb = get_pmb(); 
  /* be sure that we got a good block*/
  assert(pmb); 
  pmb->us0 =  pfa;
  pmb->vaddr     =  vaddr;
  pmb->us1 = us1;
  pmb->us2 = us2;
  /* Insert the block on the process's linked list*/
  if(!p->p_lus1_us2_size) 
      p->p_lus1_us2 = pmb;
  else{
    next_pmb = p->p_lus1_us2;
    while(next_pmb->next_pmb) 
       next_pmb = next_pmb->next_pmb; 
    next_pmb->next_pmb = pmb;
    next_pmb->next_pmb->next_pmb = NULL;
  }
  pmb->id = p->p_lus1_us2_size;
  p->p_lus1_us2_size++;  
  return(pmb);
}


int set_pe_mem_to_ro(struct proc *p, u32_t *root){
   int pte, pde;
   u32_t pde_v, pte_v, pfa; // pde entry value
   u32_t *pte_a; // page table address
   if(p->p_lus1_us2_size <= 0)
        return(OK);
   if(h_step == FIRST_RUN){
      /* Whether US0 was modified 
       * during system call handling, US1 and
       * US2 should be updated accordingly.*/
       if(handle_hme_events(p)!=OK)
          panic("vm_setpt_root_to_ro: "
            "handle_hme_events failed\n");
       free_hardening_mem_events(p);
   }
   struct pram_mem_block *pmb = p->p_lus1_us2;
   while(pmb){
      pde = I386_VM_PDE(pmb->vaddr);
      pte = I386_VM_PTE(pmb->vaddr);
      pde_v = phys_get32((u32_t) (root + pde));
      // check if the pde is present
      if(check_pt_entry(pde_v)!=OK){ 
          pmb = pmb->next_pmb;
          continue;
      }
      // read the page table address
      pte_a = (u32_t *) I386_VM_PFA(pde_v);
       /* read the page table entry value*/
      pte_v = phys_get32((u32_t) (pte_a + pte)); 
      if(check_pt_entry(pte_v)!=OK){ 
          pmb = pmb->next_pmb;
          continue;
      }
      pfa = I386_VM_PFA(pte_v);
      if((p->p_hflags & PROC_SHARING_MEM) &&
                   !(pmb->flags & WS_SHARED) && 
          ((look_up_page_in_hsr(p, pmb->vaddr))==OK)){
          pmb->flags |= WS_SHARED;
             
      }
      if((pmb->flags & H_TO_UPDATE) && 
          (pmb->us1!= MAP_NONE) && 
          (pmb->us2!=MAP_NONE) ){
        if(cpy_frames(pmb->us0, pmb->us1)!=OK)
               panic("add_region_to_ws:  "
               "first_phys failed\n"); 
         if(cpy_frames(pmb->us0, pmb->us2)!=OK)
                 panic("add_region_to_ws "
               " second_phys failed\n"); 
         pmb->flags &= ~H_TO_UPDATE;

      }
#if H_DEBUG
      printf("INITIALIZING 0x%lx pram 0x%lx " 
                     "first 0x%lx second 0x%lx\n",
              pmb->vaddr, pmb->us0, 
              pmb->us1, pmb->us2);  
     if((pmb->us1!= MAP_NONE) && 
         (pmb->us2!=MAP_NONE) && 
         (h_step == FIRST_RUN)){
       int r1, r2;
       r1 = cmp_frames(pmb->us0, pmb->us1);
       r2 = cmp_frames(pmb->us0, pmb->us2);
       if((r1!=OK) || (r2!=OK))
         printf("US1 US2  NOT THE SAME 0x%lx  "
             "pram 0x%lx temp 0x%lx 0x%lx, r1: %d "
             " r2: %d\n", pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2, r1, r2);
      }
      if((pmb->us1!=MAP_NONE) && 
         (pmb->us2!=MAP_NONE) && 
         (h_step == SECOND_RUN)){
           int r2;
           r2 = cmp_frames(pmb->us0, pmb->us2);
           if((r1!=OK) || (r2!=OK))
              printf("US2  IS NOT THE SAME 0x%lx "
                " pram 0x%lx temp 0x%lx"
                 " 0x%lx, r1: %d r2: %d\n",
                 pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2, r1, r2);
      }
#endif
      /* disable the WRITE bit*/
      if(h_step == FIRST_RUN){
         if(!pfa){
            free_pram_mem_block(p, pmb->vaddr,
                 (u32_t *)root);
            pmb = pmb->next_pmb;
            continue;
         }
         if(pmb->us1!=MAP_NONE){
            pte_v = 
             (pte_v & I386_VM_ADDR_MASK_INV) | pmb->us1;
           if(!(pmb->flags & IWS_PF_FIRST) && 
              !(pmb->flags & IWS_MOD_KERNEL) )
                 pte_v &= ~I386_VM_WRITE;
         }
         else
         pte_v &= ~I386_VM_WRITE;
        }
        else{
          if(pmb->us2!=MAP_NONE){
            pte_v = 
             (pte_v & I386_VM_ADDR_MASK_INV) | pmb->us2;
            if(!(pmb->flags & IWS_PF_SECOND) && 
               !(pmb->flags & IWS_MOD_KERNEL) )
                pte_v &= ~I386_VM_WRITE;
           }
           else
              pte_v &= ~I386_VM_WRITE;
         }
       
         if((pmb->us1!=MAP_NONE) && 
             (pmb->us2==MAP_NONE))
            pte_v = 
             (pte_v & I386_VM_ADDR_MASK_INV) | pmb->us0;
         pte_v &= ~I386_VM_DIRTY;
         /* update the page table*/
         phys_set32((u32_t) (pte_a + pte), &pte_v);
         pmb = pmb->next_pmb;
   }
   return(OK);
}


/*==========================================*
 *			vm_setpt_root_to_ro *
 *==========================================*/
/** Browse the page table from page directory O to page directory
 ** I386_VM_DIR_ENTRIES
 ** for each page directory entry the page directory is not considered
 ** if the page directory 
 **   ** Is not present
 **   ** has not write access
 **   ** Is not accessible in USER mode
 **   ** Is a global pde
 **   ** Is a big page
 ** The page table of each pde is browse and each page table entry
 ** is considered to restrict access to the processing element by calling the
 ** static void vm_setpt_to_ro(struct proc * , u32_t *, const u32_t ) **/
void vm_setpt_root_to_ro(struct proc *p, u32_t *root){

    int pde; // page directory entry
    assert(!((u32_t) root % I386_PAGE_SIZE));
    assert(p->p_nr != VM_PROC_NR); // VM is not included
    if(h_step == FIRST_RUN){
      /** Whether US0 was modified during system call handling, US1 and
       ** US2 should be updated accordingly.*/
       if(handle_hme_events(p)!=OK)
          panic("vm_setpt_root_to_ro: handle_hme_events failed\n");
       free_hardening_mem_events(p);
    }
    for(pde = 0; pde < I386_VM_DIR_ENTRIES; pde++) {
       // start from 0 to I386_VM_DIR_ENTRIES = 1024
       u32_t pde_v; // pde entry value
       u32_t *pte_a; // page table address
       // read the pde entry value
       pde_v = phys_get32((u32_t) (root + pde));
       // check if the pde is present
       if(check_pt_entry(pde_v)!=OK) continue;
       // read the page table address
       pte_a = (u32_t *) I386_VM_PFA(pde_v);
       // call the function to handle the page table entries
       vm_setpt_to_ro(p, pte_a, pde * I386_VM_PT_ENTRIES * I386_PAGE_SIZE);
    }
    return;
}

/*===========================================================================*
 *				vm_setpt_to_ro				     *
 *===========================================================================*/
 

static void vm_setpt_to_ro(struct proc *p, u32_t *pagetable, const u32_t v)
{
     /** Browse the page table entry from page table entry O to page directory
     ** I386_VM_PT_ENTRIES
     ** for each page table entry the page table is not considered
     ** if the page table entry 
     **   ** Is not present
     **   ** Is not accessible in USER mode
     **   ** the page does not map to a frame
     ** for each page the virtual address and the physical address are stored in a
     ** linked list embedded in the process data structure
     ** The page access is modified from USER mode to Kernel mode
     ** So when a page fault occur we are able to kniw if it is a normal page fault
     ** or a page fault from that access modification.  **/
     int pte; /* page table entry number*/ 
     assert(!((u32_t) pagetable % I386_PAGE_SIZE));
     assert(p->p_nr != VM_PROC_NR); /* VM is not included*/
     for(pte = 0; pte < I386_VM_PT_ENTRIES; pte++) { 
     /* start from 0 to I386_VM_PT_ENTRIES = 1024*/
	u32_t pte_v; /* page table entry value*/
        u32_t pfa ; /* frame address value*/
        /* read the page table entry value*/
	pte_v = phys_get32((u32_t) (pagetable + pte)); 
        if(check_pt_entry(pte_v)!=OK) continue;
        /* read the frame address value*/
	pfa = I386_VM_PFA(pte_v);
        /* if the frame address value is zero continue Not label that page*/
        
        /* pmb is the data structure to describe that page*/
        /* next_pmb is the data structure to put that data is the linked list*/
        struct pram_mem_block *pmb, *next_pmb; 
        u32_t vaddr = v + pte * I386_PAGE_SIZE;
        
        if(!(pmb = look_up_pte(p, I386_VM_PDE(vaddr), I386_VM_PTE(vaddr) )))
            pmb = add_pmb(p, pfa, v, pte); 
        assert(pmb);
        
        if((p->p_hflags & PROC_SHARING_MEM) &&
                   !(pmb->flags & WS_SHARED) && 
            ((look_up_page_in_hsr(p, pmb->vaddr))==OK)){
             pmb->flags |= WS_SHARED;
             
        }
#if H_DEBUG
        if(!pfa)
         printf("vaddr 0x%lx 0x%lx 0x%x\n", pmb->vaddr, pmb->us0, pfa);
        printf("INITIALIZING 0x%lx pram 0x%lx " 
                     "first 0x%lx second 0x%lx\n", pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2);

        
        if((pmb->us1!= MAP_NONE) 
            && (pmb->us2!=MAP_NONE) && (h_step == FIRST_RUN)){
           int r1, r2;
           r1 = cmp_frames(pmb->us0, pmb->us1);
           r2 = cmp_frames(pmb->us0, pmb->us2);
           if((r1!=OK) || (r2!=OK))
              printf("US1 US2  NOT THE SAME 0x%lx  pram 0x%lx temp 0x%lx"
                 " 0x%lx, r1: %d r2: %d\n", pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2, r1, r2);
        }



        if((pmb->us1!=MAP_NONE) && 
             (pmb->us2!=MAP_NONE) && (h_step == SECOND_RUN)){
           int r2;
           r2 = cmp_frames(pmb->us0, pmb->us2);
           if((r1!=OK) || (r2!=OK))
              printf("US2  IS NOT THE SAME 0x%lx  pram 0x%lx temp 0x%lx"
                 " 0x%lx, r1: %d r2: %d\n", pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2, r1, r2);
        }
#endif
        /* disable the WRITE bit*/
        if(h_step == FIRST_RUN){
            if(pmb->us1!=MAP_NONE){
               if(pmb->flags & H_FORK)
                  pte_v = (pte_v & I386_VM_ADDR_MASK_INV) | pmb->us0;
               else
                  pte_v = (pte_v & I386_VM_ADDR_MASK_INV) | pmb->us1;
               if(!(pmb->flags & IWS_PF_FIRST) && !(pmb->flags & IWS_MOD_KERNEL) )
                 pte_v &= ~I386_VM_WRITE;
            }
            else
               pte_v &= ~I386_VM_WRITE;
        }
        else{
           if(pmb->us2!=MAP_NONE){
              if(pmb->flags & H_FORK)
                  pte_v = (pte_v & I386_VM_ADDR_MASK_INV) | pmb->us0;
              else
                  pte_v = (pte_v & I386_VM_ADDR_MASK_INV) | pmb->us2;
              if(!(pmb->flags & IWS_PF_SECOND) && !(pmb->flags & IWS_MOD_KERNEL) )
                pte_v &= ~I386_VM_WRITE;
           }
           else
              pte_v &= ~I386_VM_WRITE;
        }
       
        if((pmb->us1!=MAP_NONE) && 
             (pmb->us2==MAP_NONE))
           pte_v = (pte_v & I386_VM_ADDR_MASK_INV) | pmb->us0;
        pte_v &= ~I386_VM_DIRTY;

        /* update the page table*/
        phys_set32((u32_t) (pagetable + pte), &pte_v);
     }
     return;
}

void set_fork_label(struct proc *p){
  if(p->p_lus1_us2_size <= 0)
          return;
  struct pram_mem_block *pmb = p->p_lus1_us2;
  while(pmb){
        pmb->iflags = pmb->flags;
        pmb->flags = H_FORK;
	pmb = pmb->next_pmb;
  }
}

void set_exec_label(struct proc *p){
  if(p->p_lus1_us2_size <= 0)
          return;
  struct pram_mem_block *pmb = p->p_lus1_us2;
  while(pmb){
        pmb->iflags = pmb->flags;
        pmb->flags = H_EXEC;
	pmb = pmb->next_pmb;
  }
}
