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
static struct hardening_mem_event *get_hme(void);
static int free_hardening_mem_event(struct proc *rp, int id);
/*===========================================================================*
 *				get_hme			             *
 *===========================================================================*/
/*   Return the first avalaible hme in hardening_mem_events.
 **  If the table is full a panic is triggered 
 **  otherwise the found hme is returnedtable */
static struct hardening_mem_event *get_hme(void){
    int hme_offset = 0;
    /* start from the first hme */
    struct hardening_mem_event *hme = BEG_HARDENING_MEM_EVENTS_ADDR;
    /**If the first block is free return it**/ 
	if(hme->flags & HME_SLOT_FREE) {
            /**Reset the data in the block and return the block**/
	    hme->flags &=~HME_SLOT_FREE;
            hme->next_hme = NULL;
            hme->addr_base = MAP_NONE;
            hme->nbytes = 0;
	    return hme;
	}
	do{
     /*** Otherwise go through the lus1_us2 and search the first available
      *** bloc  ***/
		hme_offset++;
		hme++;
	}while(!(hme->flags & HME_SLOT_FREE) &&
                    hme < END_HARDENING_MEM_EVENTS_ADDR);

    /**The end of the lus1_us2 is reached panic **/
        if(hme_offset>= HARDENING_MEM_EVENTS)
	   panic("ALERT BLOCK LIST EVENTS IS FULL STOP STOP %d\n", hme_offset);

        /**The bloc is found, reset the content of the bloc and return it**/
	hme->flags &=~HME_SLOT_FREE;
        hme->next_hme = NULL;
        hme->addr_base = MAP_NONE;
        hme->nbytes = 0;
	return hme;
}

int add_hme_event(struct proc *rp, 
                        vir_bytes offset, vir_bytes size){

   int pde = I386_VM_PDE(offset);
   int pte = I386_VM_PTE(offset);
   vir_bytes page_base = pde * I386_VM_PT_ENTRIES * I386_PAGE_SIZE
                            + pte * I386_PAGE_SIZE;
   int n_pages_covered = (size + (offset - page_base) - 1)/(4*1024)  + 1;
   struct hardening_mem_event * hme;
   if(!(hme = look_up_hme(rp, offset))){
      /* ask for a new pmb block in the free list*/
      hme = get_hme(); 
      struct hardening_mem_event *next_hme;
      assert(hme); /* be sure that we got a good block*/
      hme->addr_base =  offset;
      hme->nbytes    = size;
      hme->npages = n_pages_covered;
      /* Insert the block on the process's linked list*/
      if(!rp->p_nb_hardening_mem_events) rp->p_hardening_mem_events = hme;
      else{
         next_hme = rp->p_hardening_mem_events;
         while(next_hme->next_hme) next_hme = next_hme->next_hme; 
         next_hme->next_hme = hme;
         next_hme->next_hme->next_hme = NULL;
      }
      hme->id = rp->p_nb_hardening_mem_events;
      return(++rp->p_nb_hardening_mem_events);
   }
   if(hme->npages < n_pages_covered){
      hme->addr_base =  offset;
      hme->nbytes    = size;
      hme->npages = n_pages_covered;
   } 
   return(rp->p_nb_hardening_mem_events);  
}


int  handle_hme_events(struct proc *rp){
   if(rp->p_nb_hardening_mem_events <= 0)
      return(OK);
   struct hardening_mem_event *hme = rp->p_hardening_mem_events;
   while(hme){
#if H_DEBUG
     printf("#### HARDENING MEM EVENTS #### %d 0x%lx 0x%lx %d\n", 
             hme->id, hme->addr_base, hme->nbytes, hme->npages);
#endif
     if(update_range_ws_us1_us2_data(rp, hme->addr_base, hme->npages)!=OK)
        return(EFAULT);
     hme = hme->next_hme;
  }    
  return(OK);
}

/*===========================================================================*
 *				free_hardening_mem_events      	             *
 *===========================================================================*/
void free_hardening_mem_events(struct proc *rp){
   if(rp->p_nb_hardening_mem_events <= 0)
      return;
   struct hardening_mem_event *hme = rp->p_hardening_mem_events;
   int lsize = rp->p_nb_hardening_mem_events;; 
   while(hme){
        if(free_hardening_mem_event(rp, hme->id)!=--lsize)
            printf("Freeing hme with error %d\n", lsize); 
	hme = hme->next_hme;
     }
   assert(rp->p_nb_hardening_mem_events == 0);
   assert(rp->p_hardening_mem_events == NULL);	
}


/*===========================================================================*
 *				free_hardening_mem_event       	             *
 *===========================================================================*/
static int free_hardening_mem_event(struct proc *rp, int id){
   if(rp->p_nb_hardening_mem_events <= 0)
      return(0);
   struct hardening_mem_event *hme = rp->p_hardening_mem_events;
   struct hardening_mem_event *prev_hme = NULL, *next_hme = NULL;
   while(hme){
     if(hme->id == id){
        hme->flags = HME_SLOT_FREE;
        hme->id    = 0; 
        hme->addr_base =  0;
        hme->nbytes    = 0;
        hme->npages = 0;
        rp->p_nb_hardening_mem_events--;
        if(prev_hme)
          prev_hme->next_hme = hme->next_hme;
        else
          rp->p_hardening_mem_events = hme->next_hme;
        break;
     }
     prev_hme = hme;
     next_hme = hme->next_hme;
     hme = hme->next_hme;
  }
  return(rp->p_nb_hardening_mem_events);
}


/*===========================================================================*
 *				look_up_hme             	             *
 *===========================================================================*/
struct hardening_mem_event * look_up_hme(struct proc *rp, vir_bytes offset){
   if(rp->p_nb_hardening_mem_events <= 0)
     return(NULL);
   int pte = I386_VM_PTE(offset);
   int pde = I386_VM_PDE(offset);
   struct hardening_mem_event *hme = rp->p_hardening_mem_events;
   int __pte, __pde;
   while(hme){
      __pte = I386_VM_PTE(hme->addr_base);
      __pde = I386_VM_PDE(hme->addr_base);
      if((__pte==pte)&&(__pde==pde))
	  return(hme);
      hme = hme->next_hme;
   }	
   return(NULL);
}
