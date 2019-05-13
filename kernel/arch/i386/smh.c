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
static int free_hsr(struct proc *rp, int id);
static struct hardening_shared_proc *get_hsp(void);
static struct hardening_shared_region *get_hsr(void);
static struct hardening_shared_region * look_up_hsr(struct proc *rp, vir_bytes offset,
            vir_bytes length, int r_id);
static struct hardening_shared_proc * look_up_hsp(struct proc *rp, 
                struct hardening_shared_region *hsr);
static struct hardening_shared_proc * look_up_unique_hsp(struct proc *rp);
static struct hardening_shared_region * look_up_unique_hsr(int r_id);
static int add_all_hsr_s( struct hardening_shared_region * hsr);
static int add_all_hsp_s( struct hardening_shared_proc * hsp);
static int free_hsp_from_hsr(struct proc *rp, 
                   struct hardening_shared_region*hsr);
static int free_hsr_from_all_hsr_s(struct hardening_shared_region *phsr);
static int free_hsp_from_all_hsp_s(struct proc *rp);
static struct hardening_shared_region * look_up_hsr_vaddr(struct proc *rp,
         vir_bytes vaddr, vir_bytes size);

void enable_hme_event_in_procs(struct proc *rp,  
           vir_bytes vaddr, vir_bytes size ){
   if(rp->p_nb_hardening_shared_regions <= 0)
      return;
   struct hardening_shared_region *hsr = look_up_hsr_vaddr(rp, vaddr,size);
   struct hardening_shared_proc *hsp = hsr->r_hsp;
   while(hsp){
         add_hme_event(rp, vaddr, size );
         hsp = hsp->next_hsp;
   }
}

/*===========================================================================*
 *				get_hsr			             *
 *===========================================================================*/
static struct hardening_shared_region *get_hsr(void){
    int hsr_offset = 0;
    /* start from the first hsr */
    struct hardening_shared_region *hsr = BEG_HARDENING_SHARED_REGIONS_ADDR;
    /**If the first block is free return it**/ 
	if(hsr->flags & HSR_SLOT_FREE) {
            /**Reset the data in the block and return the block**/
	    hsr->flags &=~HSR_SLOT_FREE;
            hsr->next_hsr = NULL;
            hsr->vaddr = 0;
            hsr->length = 0;
            hsr->r_hsp  = NULL;
	    return hsr;  
	}
	do{
     /*** Otherwise go through the lus1_us2 and search the first available
      *** bloc  ***/
		hsr_offset++;
		hsr++;
	}while(!(hsr->flags & HSR_SLOT_FREE) &&
                    hsr < END_HARDENING_SHARED_REGIONS_ADDR);

    /**The end of the lus1_us2 is reached panic **/
        if(hsr_offset>= HARDENING_SHARED_REGIONS)
	   panic("ALERT HARDENING_SHARED_REGIONS IS FULL STOP STOP %d\n", hsr_offset);

        /**The bloc is found, reset the content of the bloc and return it**/
	hsr->flags &=~HSR_SLOT_FREE;
        hsr->next_hsr = NULL;
        hsr->vaddr = 0;
        hsr->length = 0;
        hsr->r_hsp  = NULL;
	return hsr;  
}


/*===========================================================================*
 *				get_hsp			             *
 *===========================================================================*/
static struct hardening_shared_proc *get_hsp(void){
    int hsp_offset = 0;
    /* start from the first hsp */
    struct hardening_shared_proc *hsp = BEG_HARDENING_SHARED_PROCS_ADDR;
    /**If the first block is free return it**/ 
	if(hsp->flags & HSP_SLOT_FREE) {
            /**Reset the data in the block and return the block**/
	    hsp->flags &=~HSP_SLOT_FREE;
            hsp->next_hsp = NULL;
            hsp->hsp_endpoint = 0;
	    return hsp;  
	}
	do{
     /*** Otherwise go through the lus1_us2 and search the first available
      *** bloc  ***/
		hsp_offset++;
		hsp++;
	}while(!(hsp->flags & HSP_SLOT_FREE) &&
                    hsp < END_HARDENING_SHARED_PROCS_ADDR);

    /**The end of the lus1_us2 is reached panic **/
        if(hsp_offset>= HARDENING_SHARED_PROCS)
	   panic("ALERT HARDENING_SHARED_REGIONS IS FULL STOP STOP %d\n", hsp_offset);

        /**The bloc is found, reset the content of the bloc and return it**/
	hsp->flags &=~HSP_SLOT_FREE;
        hsp->next_hsp = NULL;
        hsp->hsp_endpoint = 0;
	return hsp;   
}

/*===========================================================================*
 *				look_up_hsr             	             *
 *===========================================================================*/
static struct hardening_shared_region * look_up_hsr(struct proc *rp, vir_bytes offset,
            vir_bytes length, int r_id){
   if(rp->p_nb_hardening_shared_regions <= 0)
     return(NULL);
   struct hardening_shared_region *hsr = rp->p_hardening_shared_regions;
   while(hsr){
      if((hsr->vaddr == offset)&&
          (length == hsr->length) && (hsr->r_id == r_id))
	  return(hsr);
      hsr = hsr->next_hsr;
   }	
   return(NULL);
}

/*===========================================================================*
 *				look_up_hsp             	             *
 *===========================================================================*/
static struct hardening_shared_proc * look_up_hsp(struct proc *rp, 
                struct hardening_shared_region *hsr){
   if(hsr->n_hsp <= 0)
     return(NULL);
   struct hardening_shared_proc  *hsp = hsr->r_hsp;
   while(hsp){
      if(hsp->hsp_endpoint == rp->p_endpoint)
	  return(hsp);
      hsp = hsp->next_hsp;
   }	
   return(NULL);
}

/*===========================================================================*
 *				look_up_unique_hsp             	             *
 *===========================================================================*/
static struct hardening_shared_proc * look_up_unique_hsp(struct proc *rp){
   if(n_hsps <= 0)
     return(NULL);
   struct hardening_shared_proc  *hsp = all_hsp_s;
   while(hsp){
      if(hsp->hsp_endpoint == rp->p_endpoint)
	  return(hsp);
      hsp = hsp->next_hsp;
   }	
   return(NULL);
}


/*===========================================================================*
 *				look_up_unique_hsr             	             *
 *===========================================================================*/
static struct hardening_shared_region * look_up_unique_hsr(int r_id){
   if(n_hsrs <= 0)
     return(NULL);
   struct hardening_shared_region  *hsr = all_hsr_s;
   while(hsr){
      if(hsr->r_id == r_id)
	  return(hsr);
      hsr = hsr->next_hsr;
   }	
   return(NULL);
}

int add_hsr(struct proc *rp, vir_bytes offset, vir_bytes size, int r_id){
   struct hardening_shared_region * hsr;
   if(!(hsr = look_up_hsr(rp, offset,size, r_id))){ 
      if(!(hsr = look_up_unique_hsr(r_id))){
#if H_DEBUG
         printf("not found\n");
#endif
         hsr = get_hsr();
         hsr->vaddr =  offset;
         hsr->length    = size;
         hsr->r_id    = r_id;
         hsr->id = rp->p_nb_hardening_shared_regions;
         add_all_hsr_s(hsr);
      } 
      struct hardening_shared_region *next_hsr;
      assert(hsr); /* be sure that we got a good block*/
      if(!rp->p_nb_hardening_shared_regions) 
         rp->p_hardening_shared_regions = hsr;
      else{
         next_hsr = rp->p_hardening_shared_regions;
         while(next_hsr->next_hsr) next_hsr = next_hsr->next_hsr; 
         next_hsr->next_hsr = hsr;
         next_hsr->next_hsr->next_hsr = NULL;
      }
      add_hsp(rp,hsr);
      return(++rp->p_nb_hardening_shared_regions);
   }
   return(rp->p_nb_hardening_shared_regions);  
}


int add_hsp(struct proc *rp, struct hardening_shared_region *hsr){

   struct hardening_shared_proc * hsp;
   if(!(hsp = look_up_hsp(rp, hsr))){
      if(!(hsp=look_up_unique_hsp(rp))){
         hsp = get_hsp(); 
         hsp->hsp_endpoint =  rp->p_endpoint;
         hsp->id = hsr->n_hsp;
         add_all_hsp_s(hsp);
      }
      struct hardening_shared_proc *next_hsp;
      assert(hsp); /* be sure that we got a good block*/
      if(!hsr->n_hsp) hsr->r_hsp = hsp;
      else{
         next_hsp = hsr->r_hsp;
         while(next_hsp->next_hsp) next_hsp = next_hsp->next_hsp; 
         next_hsp->next_hsp = hsp;
         next_hsp->next_hsp->next_hsp = NULL;
      }
      return(++hsr->n_hsp);
   }
   return(hsr->n_hsp);  
}

static int add_all_hsr_s( struct hardening_shared_region * hsr){
   if(all_hsr_s==NULL){
      all_hsr_s = hsr;
      return(n_hsrs++);
   }
   struct hardening_shared_region * next_hsr;
   next_hsr = all_hsr_s;
   while(next_hsr->next_hsr) next_hsr = next_hsr->next_hsr; 
   next_hsr->next_hsr = hsr;
   next_hsr->next_hsr->next_hsr = NULL;
   return(n_hsrs++);
}

static int add_all_hsp_s( struct hardening_shared_proc * hsp){
   if(all_hsp_s==NULL){
      all_hsp_s = hsp;
      return(n_hsps++);
   }
   struct hardening_shared_proc * next_hsp;
   next_hsp = all_hsp_s;
   while(next_hsp->next_hsp) next_hsp = next_hsp->next_hsp; 
   next_hsp->next_hsp = hsp;
   next_hsp->next_hsp->next_hsp = NULL;
   return(n_hsps++);
}

void display_all_hsp_s(void){
  struct hardening_shared_proc * hsp = all_hsp_s;
  while(hsp){
    printf("#### Process in all_hsp_s #### %d %d %d\n", 
             hsp->id, hsp->flags, hsp->hsp_endpoint);
         hsp = hsp->next_hsp;
  }
}

void display_all_hsr_s(void){
  struct hardening_shared_region * hsr = all_hsr_s;
  while(hsr){
    printf("#### HARDENING SHARED REGIONS #### %d 0x%lx 0x%lx\n", 
             hsr->id, hsr->vaddr, hsr->length);
         hsr = hsr->next_hsr;
  }
}
/*===========================================================================*
 *				free_hsr       	             *
 *===========================================================================*/
static int free_hsr(struct proc *rp, int id){
   struct hardening_shared_region *hsr = rp->p_hardening_shared_regions;
   struct hardening_shared_region *prev_hsr = NULL, *next_hsr = NULL;
   while(hsr){
     if(hsr->id == id){
        free_hsp_from_hsr(rp, hsr);
        if(hsr->r_hsp == NULL){
          hsr->flags = HSR_SLOT_FREE;
          hsr->id    = 0; 
          hsr->vaddr =  0;
          hsr->length    = 0;
          free_hsr_from_all_hsr_s(hsr);
        }
        rp->p_nb_hardening_shared_regions--;
        if(prev_hsr)
          prev_hsr->next_hsr = hsr->next_hsr;
        else
          rp->p_hardening_shared_regions = hsr->next_hsr;
        break;
     }
     prev_hsr = hsr;
     next_hsr = hsr->next_hsr;
     hsr = hsr->next_hsr;
  }
  return(rp->p_nb_hardening_shared_regions);
}

static int free_hsp_from_hsr(struct proc *rp, 
                   struct hardening_shared_region*hsr){
  struct hardening_shared_proc *hsp = hsr->r_hsp;
  struct hardening_shared_proc *prev_hsp = NULL, *next_hsp = NULL; 
  while(hsp){
     if(hsp->hsp_endpoint == rp->p_endpoint){
        hsr->n_hsp--;
        if(prev_hsp)
          prev_hsp->next_hsp = hsp->next_hsp;
        else
          hsr->r_hsp = hsp->next_hsp;
        break;
     }
     prev_hsp = hsp;
     next_hsp = hsp->next_hsp;
     hsp = hsp->next_hsp;
  }
  return(hsr->n_hsp);  
}

static int free_hsr_from_all_hsr_s(struct hardening_shared_region *phsr){
  struct hardening_shared_region *hsr = all_hsr_s;
  struct hardening_shared_region *prev_hsr = NULL, *next_hsr = NULL; 
  while(hsr){
     if(hsr->r_id == phsr->r_id){
       n_hsrs--;
       if(prev_hsr)
          prev_hsr->next_hsr = hsr->next_hsr;
       else
          all_hsr_s = hsr->next_hsr;
       break;
     }
     prev_hsr = hsr;
     next_hsr = hsr->next_hsr;
     hsr = hsr->next_hsr;
  }
  return(n_hsrs);
}

static int free_hsp_from_all_hsp_s(struct proc *rp){
  struct hardening_shared_proc *hsp = all_hsp_s;
  struct hardening_shared_proc *prev_hsp = NULL, *next_hsp = NULL; 
  while(hsp){
     if(hsp->hsp_endpoint == rp->p_endpoint){
       n_hsps--;
       hsp->hsp_endpoint = 0;
       hsp->flags = HSP_SLOT_FREE;
       hsp->id = 0;
       if(prev_hsp)
          prev_hsp->next_hsp = hsp->next_hsp;
       else
          all_hsp_s = hsp->next_hsp;
       break;
     }
     prev_hsp = hsp;
     next_hsp = hsp->next_hsp;
     hsp = hsp->next_hsp;
  }
  return(n_hsps);
}

/*===========================================================================*
 *				free_hsrs      	             *
 *===========================================================================*/
void free_hsrs(struct proc *rp){
   if(rp->p_nb_hardening_shared_regions <= 0)
      return;
   struct hardening_shared_region *hsr = rp->p_hardening_shared_regions;
   int lsize = rp->p_nb_hardening_shared_regions; 
   while(hsr){
        if(free_hsr(rp, hsr->id)!=--lsize)
            printf("Freeing hsr with error %d\n", lsize); 
	hsr = hsr->next_hsr;
     }
   assert(rp->p_nb_hardening_shared_regions == 0);
   assert(rp->p_hardening_shared_regions == NULL);
   free_hsp_from_all_hsp_s(rp);	
}

void  handle_hsr_events(struct proc *rp){
   if(rp->p_nb_hardening_shared_regions <= 0)
      return;
   struct hardening_shared_region *hsr = rp->p_hardening_shared_regions;
   while(hsr){
     printf("#### HARDENING SHARED REGIONS #### %d 0x%lx 0x%lx\n", 
             hsr->id, hsr->vaddr, hsr->length);
     printf("#### REGIONS SHARED WITH ####\n");
     struct hardening_shared_proc *hsp = hsr->r_hsp;
     while(hsp){
         printf("#### Process sharing region #### %d %d %d\n", 
             hsp->id, hsp->flags, hsp->hsp_endpoint);
         hsp = hsp->next_hsp;
     }
     hsr = hsr->next_hsr;
  }    
}

int look_up_page_in_hsr(struct proc *rp, vir_bytes vaddr){
    if(rp->p_nb_hardening_shared_regions <= 0)
      return(VM_VADDR_NOT_FOUND);
    if(!(rp->p_hflags & PROC_SHARING_MEM))
      return(PROC_NOT_SHARING);
    struct hardening_shared_region *hsr = rp->p_hardening_shared_regions;
    while(hsr){
         if((hsr->vaddr <= vaddr) && (vaddr <= hsr->vaddr + hsr->length)){
            return(OK);
         }
         hsr = hsr->next_hsr;
    }
    return(VM_VADDR_NOT_FOUND);
}


static struct hardening_shared_region * look_up_hsr_vaddr(struct proc *rp,
         vir_bytes vaddr, vir_bytes size){
   if(rp->p_nb_hardening_shared_regions <= 0)
     return(NULL);
   struct hardening_shared_region *hsr = rp->p_hardening_shared_regions;
   while(hsr){
      if((hsr->vaddr <= (vaddr + size)) &&
          ((vaddr + size) <= hsr->vaddr + hsr->length))
	  return(hsr);
      hsr = hsr->next_hsr;
   }	
   return(NULL);
}
