/*** Here the copy-on-write is implemented
 *** - The function vm_setpt_root_to_ro
 ***    modify the page table entries of the hardened 
 ***   process, All the USER accessed pages are set to NOT USER
 ***   Author: Emery Kouassi Assogba
 ***   Email: assogba.emery@gmail.com
 ***   Phone: 0022995222073
 ***   22/01/2019 lln***/

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


#define I386_VM_ADDR_MASK_INV  0x00000FFF
static void vm_setpt_to_ro(struct proc *p, u32_t *pagetable, const u32_t v);
static struct pram_mem_block *get_pmb(void);
static void vm_resetmem(struct proc *p, u32_t *pagetable, const u32_t v);
static int look_up_unique_pte(struct proc *current_p, int pde, int pte);
static int deadlock(int function, register struct proc *cp, endpoint_t src_dst_e);
static int update_ws_us1_us2_data_pmb(struct proc *rp, struct pram_mem_block *pmb);
static struct hardening_mem_event *get_hme(void);
static int free_hardening_mem_event(struct proc *rp, int id);
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
static int look_up_page_in_hsr(struct proc *rp, vir_bytes vaddr);
static struct hardening_shared_region * look_up_hsr_vaddr(struct proc *rp,
         vir_bytes vaddr, vir_bytes size);
static void enable_hme_event_in_procs(struct proc *p,  
           vir_bytes vaddr, vir_bytes size );
static struct pram_mem_block * add_pmb(struct proc *p, phys_bytes pfa, 
      vir_bytes v, int pte);
static struct pram_mem_block * add_pmb_vaddr(struct proc *p, phys_bytes pfa, 
      vir_bytes vaddr, phys_bytes us1, phys_bytes us2);
static int check_pt_entry(u32_t pte_v);
static int check_vaddr_2(struct proc *p, u32_t *root, vir_bytes vaddr, int *rw);
static void restore_cr_reg(void);

/*===========================================================================*
 *			vm_setpt_root_to_ro                                  *
 *===========================================================================*/
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
               pte_v = (pte_v & I386_VM_ADDR_MASK_INV) | pmb->us1;
               if(!(pmb->flags & IWS_PF_FIRST) && !(pmb->flags & IWS_MOD_KERNEL) )
                 pte_v &= ~I386_VM_WRITE;
            }
            else
               pte_v &= ~I386_VM_WRITE;
        }
        else{
           if(pmb->us2!=MAP_NONE){
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

/*===========================================================================*
 *				get_pmb				             *
 *===========================================================================*/
/*   Return the first avalaible pmb in working_set table.
 **  If the table is full a panic is triggered 
 **  otherwise the found pmb is returnedtable */
static struct pram_mem_block *get_pmb(void){
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
     /*** Otherwise go through the working_set and search the first available
      *** bloc  ***/
		hme_offset++;
		hme++;
	}while(!(hme->flags & HME_SLOT_FREE) &&
                    hme < END_HARDENING_MEM_EVENTS_ADDR);

    /**The end of the working_set is reached panic **/
        if(hme_offset>= HARDENING_MEM_EVENTS)
	   panic("ALERT BLOCK LIST EVENTS IS FULL STOP STOP %d\n", hme_offset);

        /**The bloc is found, reset the content of the bloc and return it**/
	hme->flags &=~HME_SLOT_FREE;
        hme->next_hme = NULL;
        hme->addr_base = MAP_NONE;
        hme->nbytes = 0;
	return hme;
}

/*==============================================*
 *		save_copy_0                     *
 *==============================================*/
void save_copy_0(struct proc* p){
   gs = (u16_t)p->p_reg.gs;
   fs = (u16_t)p->p_reg.fs;
   es = (u16_t)p->p_reg.es;
   ds = (u16_t)p->p_reg.ds;
   di = (reg_t)p->p_reg.di;
   si = (reg_t)p->p_reg.si;
   fp = (reg_t)p->p_reg.fp;
   bx = (reg_t)p->p_reg.bx;
   dx = (reg_t)p->p_reg.dx;
   cx = (reg_t)p->p_reg.cx;
   retreg = (reg_t)p->p_reg.retreg;
   pc = (reg_t)p->p_reg.pc;
   psw = (reg_t)p->p_reg.psw;
   sp = (reg_t)p->p_reg.sp;
   cs = (reg_t)p->p_reg.cs;
   ss = (reg_t)p->p_reg.ss;
   p_kern_trap_style = 
       (int) p->p_seg.p_kern_trap_style;
   p_rts_flags = p->p_rts_flags;
   cr0 = read_cr0();
   cr2 = read_cr2();
   cr3 = read_cr3();
   cr4 = read_cr4();	 
}

/*==============================================*
 *			restore_copy_0          *
 *==============================================*/
void restore_copy_0(struct proc* p){
   p->p_reg.gs = (u16_t)gs;
   p->p_reg.fs = (u16_t)fs;
   p->p_reg.es = (u16_t)es;
   p->p_reg.ds = (u16_t)ds;
   p->p_reg.di = (reg_t)di;
   p->p_reg.si = (reg_t)si;
   p->p_reg.fp = (reg_t)fp;
   p->p_reg.bx = (reg_t)bx;
   p->p_reg.dx = (reg_t)dx;
   p->p_reg.cx = (reg_t)cx;
   p->p_reg.psw = (reg_t)psw;
   p->p_reg.sp = (reg_t)sp;
   p->p_reg.pc = (reg_t)pc;
   p->p_reg.cs = (reg_t)cs;
   p->p_reg.ss = (reg_t)ss;
   p->p_reg.retreg = (reg_t)retreg;
   p->p_seg.p_kern_trap_style = 
             (int)p_kern_trap_style;
   p->p_rts_flags = p_rts_flags;
   write_cr0(cr0);
   write_cr3(cr3);
   write_cr4(cr4);	
}

/*===============================================*
 *		hardening_exception_handler      *
 *===============================================*/
void hardening_exception_handler(
     struct exception_frame * frame){
    /*
     * running process should be the current 
     * hardenning process
     * the running process should not be the VM
     * the hardening should be enable
     * This function check if the nature of the 
     * exception. The exception is 
     * handled by hardening_exception_handler in 
     * three case
     *     - NMI, so the exception is come from 
     * the retirmen counter
     *     - MCA/MCE the exception is come from 
     * the MCA/MCE module
     *     - A pagefault occur
     * In all others cases the PE is stopped
     */
#if INJECT_FAULT
   restore_cr_reg();
#endif
   /**This function should be called 
    * when hardening is enable**/
   assert(h_enable);
   /*get the running process*/
   struct proc  *p = get_cpulocal_var(proc_ptr);
   /**The running process should 
    * be a hardened process**/
   assert(h_proc_nr == p->p_nr);
   assert(h_proc_nr != VM_PROC_NR);
   h_stop_pe = H_YES;
   switch(frame->vector){
      case DIVIDE_VECTOR :
           break;
      case DEBUG_VECTOR :
           break;
      case NMI_VECTOR :
           printf("#### GOT NMI HAHAHA %d %d %d####", 
            h_step,h_proc_nr,p->p_nr);
           if(handle_ins_counter_over()!=OK);
             h_stop_pe = H_NO;   
           break;
      case BREAKPOINT_VECTOR:
           break;
      case OVERFLOW_VECTOR:
           break;
      case BOUNDS_VECTOR:
           break;
      case INVAL_OP_VECTOR:
           break;
      case COPROC_NOT_VECTOR:
           break;
      case DOUBLE_FAULT_VECTOR:
           break;
      case COPROC_SEG_VECTOR:
           break;
      case INVAL_TSS_VECTOR:
           break;
      case SEG_NOT_VECTOR:
           break;
      case STACK_FAULT_VECTOR:
           break;
      case PROTECTION_VECTOR:
           break;
      case PAGE_FAULT_VECTOR :
           /**reset the hardening data**/
           /*** ADD COMMENT : TODO */
           h_normal_pf = 0;
           h_rw = 0; 
           /**read the virtual address 
            *where the page fault occurred**/
           reg_t pagefaultcr2 = read_cr2();
           /*** Check the nature of the pagefault:
            * if it is caused by hardening
            **  check_r = OK else 
            *   check_r = H_HANDLED_PF**/   
           int check_r = 
             check_vaddr_2(p,
                   (u32_t *)p->p_seg.p_cr3, 
                   pagefaultcr2, &h_rw);
           /**set hardening data to 
            * inform the kernel**/
           /***  TODO CHANGE THE COMPARISON ****/
           if(check_r==OK)
              h_stop_pe = H_NO;
           else 
             h_normal_pf = NORMAL_PF;       
           break;
      
      case COPROC_ERR_VECTOR:
           break;
      case ALIGNMENT_CHECK_VECTOR:
           break;
      case MACHINE_CHECK_VECTOR:
           mca_mce_handler();
           break;
      case SIMD_EXCEPTION_VECTOR:
           break; 
      default :
           panic("Unkown exception vector in"
             "hardening_exception_handler");
           break;

   }
   
   return;
}



/*============================================*
 *		check_vaddr_2                 *
 *============================================*/

static int check_vaddr_2(struct proc *p, 
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
        (h_step == SECOND_RUN));
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
         pte_v = (pte_v & I386_VM_ADDR_MASK_INV) |  
              I386_VM_WRITE | pmb->us1;
         pmb->flags |= IWS_PF_FIRST;
      }
      else  if(h_step == SECOND_RUN){
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
   if(current_p->p_first_step_workingset_id > 0){
      struct pram_mem_block *pmb = 
           current_p->p_working_set;
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
  if(current_p->p_first_step_workingset_id > 0){
     struct pram_mem_block *pmb = current_p->p_working_set;
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

/*===========================================================================*
 *				look_up_lastpf_pte           	             *
 *===========================================================================*/
struct pram_mem_block * look_up_lastpf_pte(struct proc *current_p, int normal){
	if(current_p->p_first_step_workingset_id > 0){
		struct pram_mem_block *pmb = current_p->p_working_set;
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

/*==============================================*
 *			hardening_task          *
 *==============================================*/
void hardening_task(void){
    /*
     * This function is called to end the PE execution.
     * Either the 1st execution it should start 
     *  the second execution
     * Either the 2nd execution 
     *  it should start the comprison phase
     * running process should be the current
     *  hardenning process
     * The running process should not be the VM
     * The hardening should be enable
     */
#if INJECT_FAULT
    restore_cr_reg();
#endif
    assert(h_enable);
    struct proc  *p = get_cpulocal_var(proc_ptr);
    assert(h_proc_nr == p->p_nr);
    assert(h_proc_nr != VM_PROC_NR);
    /* Should only be called during 1st or 2nd run */
    assert((h_step == FIRST_RUN) || 
       (h_step == SECOND_RUN)); 
    save_context(p);
    if(h_step == FIRST_RUN){ 
       /* End of the 1st execution */
       assert(h_restore==0);
       /* remember to restore the state 0 */
       h_restore = RESTORE_FOR_SECOND_RUN; 
       /* set the page in the working set to first_phys
        *copy the content of us0 to us1 and the content 
        * of pram2_phys to us0*/
       vm_reset_pram(p, (u32_t *)p->p_seg.p_cr3, 
           CPY_RAM_FIRST); 
       /* launch the second run */
#if H_DEBUG
       printf("ENDING FISRT RUN %d %d\n", 
         p->p_nr, origin_syscall);
#endif
       run_proc_2(p);
       /*not reachable go directly to 
        the hardening process */
       NOT_REACHABLE;
    }
    else if(h_step == SECOND_RUN){
#if H_DEBUG
          printf("ENDING SECOND RUN %d %d\n", 
            p->p_nr, origin_syscall);
#endif
          /* comparison of context1 and context 2. 
           * Here we compare the saved 
           * registers */
          if(!cmp_reg(p) || cmp_mem(p)!=OK){
          /* That means the system is in unstable state
           *  because the comparison stage failed.
           *  The solution is to cancel all 
           *  thing that fault
           * trigger in the system. The main 
           * objective is to
           * keep the effect of that event 
           * in the kernel.
           * it should certainly not be spread 
           * to the rest of the system**/
             h_unstable_state = H_UNSTABLE;
#if H_DEBUG
             printf("context non identique %d %d\n",
               p->p_endpoint, h_normal_pf);
#endif
             vm_reset_pram(p,(u32_t *)p->p_seg.p_cr3,
                 CMP_FAILED);
             h_restore = RESTORE_FOR_FISRT_RUN;
             /** Prevent the PE from running**/
             p->p_rts_flags |= RTS_UNSTABLE_STATE;
             return;
          }
          
       /* copy of us2 to us0 */
       vm_reset_pram(p,(u32_t *)p->p_seg.p_cr3,
               CPY_RAM_PRAM);

      /* reset of hardening global variables */
       h_enable = 0;
       h_proc_nr = 0;
       h_step_back = 0;
       h_step = 0;
       h_do_sys_call = 0;
       h_do_nmi = 0;
       vm_should_run = 0;
       pe_should_run = 0;
       h_restore = 0; 
       h_normal_pf = 0;
       h_pf_handle_by_k = 0;
        /** The system is in stable state**/
       h_unstable_state = H_STABLE; 
       /** a normal page fault occur 
        * where the pqge is not in the working set**/
       
       h_rw = 0; 
        /** Reset the instruction counter process**/
       p->p_start_count_ins = 0;
       id_current_pe++; // Comment TODO
       pagefault_addr_1 = 0;
       pagefault_addr_2 = 0;
#if H_DEBUG_2
       printf("PE OK #ws: %d #us1_us2: %d\n",
            p->p_second_step_workingset_id,
                       p->p_first_step_workingset_id);
#endif
       return;
   }
   else{
      panic("UNKOWN HARDENING STEP %d\n", h_step);
   }
      
}


/*===========================================*
 *				run_proc_2   *
 *===========================================*/
void run_proc_2(struct proc *p)
{
    /* This the standard switch_to_user 
     * function of Minix 3 without
     * kernel verification already performed 
     * before FIRST RUN
     */
    /* update the global variable "get_cpulocal_var" 
     * which is a Minix Macro
     */
	get_cpulocal_var(proc_ptr) = p;

	switch_address_space(p);
        /** Stop counting CPU cycle for the KERNEL**/
	context_stop(proc_addr(KERNEL));

	/* If the process isn't the owner of FPU, 
         * enable the FPU exception */
	if(get_cpulocal_var(fpu_owner) != p)
		enable_fpu_exception();
	else
		disable_fpu_exception();

#if defined(__i386__)
  	assert(p->p_seg.p_cr3 != 0);
#elif defined(__arm__)
	assert(p->p_seg.p_ttbr != 0);
#endif	
	restart_local_timer();

	/*
	 * restore_user_context() carries out the 
         * actual mode switch from kernel
	 * to userspace. This function does not return
	 */
	restore_user_context(p);
	NOT_REACHABLE;
}
/*===========================================================================*
 *				free_pram_mem_blocks           	             *
 *===========================================================================*/
void free_pram_mem_blocks(struct proc *current_p, int no_msg_to_vm){
     /** Delete of the blokcs in the PE working set list. If the working 
      ** set list is empty the function return. Otherwise each blocks is delete
      ** A the end of the function the working set of the PE should be empty ***/
     if(current_p->p_first_step_workingset_id <= 0)
          return;
     struct pram_mem_block *pmb = current_p->p_working_set;
     while(pmb){
        if((pmb->flags & H_TO_UPDATE) && (no_msg_to_vm == FROM_EXEC)){
           pmb = pmb->next_pmb;
           continue;
        }
        free_pram_mem_block(current_p, 
              pmb->vaddr, (u32_t *)current_p->p_seg.p_cr3);
	pmb = pmb->next_pmb;
     }
     if(no_msg_to_vm != FROM_EXEC){
        assert(current_p->p_first_step_workingset_id == 0);
        assert(current_p->p_working_set == NULL);	
     }
}

/*==============================================*
 *		free_pram_mem_blocks            *
 *==============================================*/
void free_pram_mem_block_vaddr(struct proc *rp,
     vir_bytes raddr, int len){
   if(rp->p_first_step_workingset_id <= 0)
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
     printf("KERNEL FREEPMBS %d\n", rp->p_endpoint);
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

/*===============================================*
 *				cmp_mem          *
 *===============================================*/

int cmp_mem(struct proc *p){
   if(p->p_first_step_workingset_id <= 0)
          return(OK);
   int r = OK;
   struct pram_mem_block *pmb = p->p_working_set;
   p->p_second_step_workingset_id = 0;
     while(pmb){
      if((pmb->us2 == MAP_NONE) || 
          (pmb->us1 == MAP_NONE)){
           pmb = pmb->next_pmb;
           continue;
      }    
      if(pmb->flags & FWS){
         p->p_second_step_workingset_id++;
         if((r = cmp_frames(pmb->us2, pmb->us1))!=OK){
            printf("&&& diff vaddr 0x%lx pram 0x%lx "
              " temp 0x%lx 0x%lx\n", pmb->vaddr,
                 pmb->us0, pmb->us1, pmb->us2);
            return (r);
         }
         pmb->flags &= ~FWS;
#if H_DEBUG
         printf("IN FINAL WORKING SET 0x%lx pram 0x%lx " 
                     "first 0x%lx second 0x%lx\n",
                 pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2);
#endif
      }
      pmb = pmb->next_pmb;
     }
    return (r);
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
   if(current_p->p_first_step_workingset_id <= 0)
      return;
   struct pram_mem_block *pmb = 
            current_p->p_working_set; 
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
        current_p->p_first_step_workingset_id--;
        if(prev_pmb)
          prev_pmb->next_pmb = pmb->next_pmb;
        else
          current_p->p_working_set = pmb->next_pmb;
        break;
     }
     prev_pmb = pmb;
     next_pmb = pmb->next_pmb;
     pmb = pmb->next_pmb;
  }
}
/*============================================*
 *		update_step                   *
 *============================================*/
void update_step(int step, int p_nr, const char *from){
   /**Change the hardening step to step**/
#if H_DEBUG
   printf("changing step from %s for %d "
          "last step %d new step %d\n", 
           from, p_nr, h_step, step);
#endif
   h_step = step;
}

/*===========================================*
 *				cmp_reg      *
 *===========================================*/
int cmp_reg(struct proc *p){
   /** Compare registers from first run and second run
    ** If one pair of register is different the return
    *  value is 0
    ** Otherwise the return value is non NULL
    ** The function compares also the origin of the 
    *  trap, fault, or interrupt
    ** for the two runs. If they are not the same, 
    *  the return value is 0***/
#if H_DEBUG
   printf("****in cmp back (current) p %d"
	" gs 0x%x fs 0x%x es 0x%x ds 0x%x di 0x%x\n"
	" si 0x%x fp 0x%x bx 0x%x****\n "
	" dx 0x%x cx 0x%x retreg 0x%x  pc 0x%x"
        " cs 0x%x\n"
	" psw 0x%x sp 0x%x ss 0x%x ****\n",
	p->p_endpoint,
	p->p_reg.gs,
	p->p_reg.fs,
	p->p_reg.es,
	p->p_reg.ds,
	p->p_reg.di,
	p->p_reg.si,
	p->p_reg.fp,
	p->p_reg.bx,
	p->p_reg.dx,
	p->p_reg.cx,
	p->p_reg.retreg,
	p->p_reg.pc,
	p->p_reg.cs,
	p->p_reg.psw,
	p->p_reg.sp,
	p->p_reg.ss);
    printf("****in cmp back (:1) p %d\n"
	"gs 0x%x fs 0x%x es 0x%x ds 0x%x di 0x%x\n"
	"si 0x%x fp 0x%x  bx 0x%x****\n "
	"dx 0x%x cx 0x%x retreg 0x%x  pc 0x%x "
        "cs 0x%x\n"
	"psw 0x%x sp 0x%x ss 0x%x ****\n"
        "eax 0x%x ebx 0x%x ecx 0x%x edx 0x%x esi "
        "0x%x edi 0x%x\n"
        "esp 0x%x ebp 0x%x origin %d\n",
	p->p_endpoint,
	gs_1,
	fs_1,
	es_1,
	ds_1,
	di_1,
	si_1,
	fp_1,
	bx_1,
	dx_1,
	cx_1,
	retreg_1,
	pc_1,
	cs_1,
	psw_1,
	sp_1,
	ss_1,
        eax_s1,
        ebx_s1,
        ecx_s1,
        edx_s1,
        esi_s1,
        edi_s1,
        esp_s1,
        ebp_s1,
        origin_1);

     printf("****in cmp back (:2) p %d\n"
	"gs 0x%x fs 0x%x es 0x%x ds 0x%x di 0x%x\n"
	"si 0x%x fp 0x%x  bx 0x%x****\n "
	"dx 0x%x cx 0x%x retreg 0x%x pc 0x%x cs 0x%x\n"
	"psw 0x%x sp 0x%x ss 0x%x****\n"
        "eax 0x%x ebx 0x%x ecx 0x%x edx 0x%x esi"
        " 0x%x edi 0x%x\n"
        "esp 0x%x ebp 0x%x origin %d\n",
	p->p_endpoint,
	gs_2,
	fs_2,
	es_2,
	ds_2,
	di_2,
	si_2,
	fp_2,
	bx_2,
	dx_2,
	cx_2,
	retreg_2,
	pc_2,
	cs_2,
	psw_2,
	sp_2,
	ss_2,
        eax_s2,
        ebx_s2,
        ecx_s2,
        edx_s2,
        esi_s2,
        edi_s2,
        esp_s2,
        ebp_s2,
        origin_2);
#endif
   return (
        (gs_1 == gs_2) &&
	(fs_1 == fs_2) &&
	(es_1 == es_2) &&
	(ds_1 == ds_2) &&
	(di_1 == di_2) &&
	(si_1 == si_2) &&
	(fp_1 == fp_2) &&
	(bx_1 == bx_2) &&
	(dx_1 == dx_2) &&
	(cx_1 == cx_2) &&
	(retreg_1 == retreg_2) &&
	(pc_1 == pc_2) &&
	(cs_1 == cs_2) &&
	(psw_1 == psw_2) &&
	(sp_1 == sp_2)   &&
	(ss_1 == ss_2)   &&
        (origin_1 == origin_2) &&
        (eax_s1 == eax_s2) &&
        (ebx_s1 == ebx_s2) &&
        (ecx_s1 == ecx_s2) &&
        (edx_s1 == edx_s2) &&
        (esi_s1 == esi_s2) &&
        (edi_s1 == edi_s2) &&
        (esp_s1 == esp_s2) &&
        (ebp_s1 == ebp_s2) &&
        (pagefault_addr_1 == pagefault_addr_2) &&
        (cr0_1 == cr0_2) &&
        (cr2_1 == cr2_2) &&
        (cr3_1 == cr3_2) &&
        (cr4_1 == cr4_2) 
     );
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
   assert((h_step == FIRST_RUN) || 
         (h_step == SECOND_RUN));
   if(p->p_first_step_workingset_id <= 0)
      return;
   struct pram_mem_block *pmb = p->p_working_set;
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

/*===========================================*
 *				save_copy_1  *
 *===========================================*/
void save_copy_1(struct proc *p){
   gs_1 = p->p_reg.gs;
   fs_1 = p->p_reg.fs;
   es_1 = p->p_reg.es;
   ds_1 = p->p_reg.ds;
   di_1 = p->p_reg.di;
   si_1 = p->p_reg.si;
   fp_1 = p->p_reg.fp;
   bx_1 = p->p_reg.bx;
   dx_1 = p->p_reg.dx;
   cx_1 = p->p_reg.cx;
   retreg_1 = p->p_reg.retreg;
   pc_1 = p->p_reg.pc;
   cs_1 = p->p_reg.cs;
   psw_1 = p->p_reg.psw;
   sp_1 = p->p_reg.sp;
   ss_1 = p->p_reg.ss;
   p_kern_trap_style_1 = 
        (int) p->p_seg.p_kern_trap_style;
   origin_1 = origin_syscall;
   eax_s1 = eax_s;
   ebx_s1 = ebx_s;
   ecx_s1 = ecx_s;
   edx_s1 = edx_s;
   esi_s1 = esi_s;
   edi_s1 = edi_s;
   esp_s1 = esp_s;
   ebp_s1 = ebp_s;
   cr0_1  = read_cr0();
   cr2_1  = read_cr2();
   cr3_1  = read_cr3();
   cr4_1 =  read_cr4();
}


/*==========================================*
 *				save_copy_2 *
 *==========================================*/
void save_copy_2(struct proc *p){
   gs_2 = p->p_reg.gs;
   fs_2 = p->p_reg.fs;
   es_2 = p->p_reg.es;
   ds_2 = p->p_reg.ds;
   di_2 = p->p_reg.di;
   si_2 = p->p_reg.si;
   fp_2 = p->p_reg.fp;
   bx_2 = p->p_reg.bx;
   dx_2 = p->p_reg.dx;
   cx_2 = p->p_reg.cx;
   retreg_2 = p->p_reg.retreg;
   pc_2 = p->p_reg.pc;
   cs_2 = p->p_reg.cs;
   psw_2 = p->p_reg.psw;
   sp_2 = p->p_reg.sp;
   ss_2 = p->p_reg.ss;
   p_kern_trap_style_2 = 
       (int) p->p_seg.p_kern_trap_style;
   origin_2 = origin_syscall;
   eax_s2 = eax_s;
   ebx_s2 = ebx_s;
   ecx_s2 = ecx_s;
   edx_s2 = edx_s;
   esi_s2 = esi_s;
   edi_s2 = edi_s;
   esp_s2 = esp_s;
   ebp_s2 = ebp_s;
   cr0_2  = read_cr0();
   cr2_2  = read_cr2();
   cr3_2  = read_cr3();
   cr4_2  = read_cr4();
}

/*===========================================================================*
 *				restore_copy_1             	             *
 *===========================================================================*/
void restore_copy_1(struct proc* p){
  p->p_reg.gs = (u16_t)gs_1;
  p->p_reg.fs = (u16_t)fs_1;
  p->p_reg.es = (u16_t)es_1;
  p->p_reg.ds = (u16_t)ds_1;
  p->p_reg.di = (reg_t)di_1;
  p->p_reg.si = (reg_t)si_1;
  p->p_reg.fp = (reg_t)fp_1;
  p->p_reg.bx = (reg_t)bx_1;
  p->p_reg.dx = (reg_t)dx_1;
  p->p_reg.cx = (reg_t)cx_1;
  p->p_reg.retreg = (reg_t)retreg_1;
  p->p_reg.pc = (reg_t)pc_1;
  p->p_reg.cs = (reg_t)cs_1;
  p->p_reg.psw = (reg_t)psw_1;
  p->p_reg.sp = (reg_t)sp_1;
  p->p_reg.ss = (reg_t)ss_1;
  p->p_seg.p_kern_trap_style = (int)p_kern_trap_style_1;
  write_cr0(cr0_1);
  write_cr3(cr3_1);
  write_cr4(cr4_1);		
}

/*===========================================================================*
 *				sendmsg2vm              	             *
 *===========================================================================*/
int sendmsg2vm(struct proc * pr){
     message m;
     int err;
     m.m_source = pr->p_endpoint;
     m.m_type   = VM_HCONFMEM;
     /* Check for a possible deadlock before actually blocking. */
     if (deadlock(SEND, pr, VM_PROC_NR)) {
                hmini_receive(pr, VM_PROC_NR, 
                   &proc_addr(VM_PROC_NR)->p_sendmsg, 0);
		return(ELOCKED);
     }

     if ((err = mini_send(pr, VM_PROC_NR,
					&m, FROM_KERNEL))) {
		panic("WARNING: pagefault: mini_send returned %d\n", err);
     }
     return err;
}

/*===========================================================================*
 *				display_mem              	             *
 *===========================================================================*/
void display_mem(struct proc *current_p){
   if(current_p->p_first_step_workingset_id > 0){
	struct pram_mem_block *pmb = current_p->p_working_set;
	while(pmb){
          if(pmb->us0!=MAP_NONE)
	  printf("displaying vaddr 0x%lx  pram 0x%lx first 0x%lx second: 0x%lx\n", 
                 pmb->vaddr, pmb->us0, 
                 pmb->us1, pmb->us2);
			pmb = pmb->next_pmb;
	}
    }
}


/*===========================================================================*
 *				deadlock				     * 
 *===========================================================================*/
static int deadlock(function, cp, src_dst_e) 
int function;					/* trap number */
register struct proc *cp;			/* pointer to caller */
endpoint_t src_dst_e;				/* src or dst process */
{
/* Check for deadlock. This can happen if 'caller_ptr' and 'src_dst' have
 * a cyclic dependency of blocking send and receive calls. The only cyclic 
 * depency that is not fatal is if the caller and target directly SEND(REC)
 * and RECEIVE to each other. If a deadlock is found, the group size is 
 * returned. Otherwise zero is returned. 
 */
  register struct proc *xp;			/* process pointer */
  int group_size = 1;				/* start with only caller */
#if DEBUG_ENABLE_IPC_WARNINGS
  static struct proc *processes[NR_PROCS + NR_TASKS];
  processes[0] = cp;
#endif

  while (src_dst_e != ANY) { 			/* check while process nr */
      int src_dst_slot;
      okendpt(src_dst_e, &src_dst_slot);
      xp = proc_addr(src_dst_slot);		/* follow chain of processes */
      assert(proc_ptr_ok(xp));
      assert(!RTS_ISSET(xp, RTS_SLOT_FREE));
#if DEBUG_ENABLE_IPC_WARNINGS
      processes[group_size] = xp;
#endif
      group_size ++;				/* extra process in group */

      /* Check whether the last process in the chain has a dependency. If it 
       * has not, the cycle cannot be closed and we are done.
       */
      if((src_dst_e = P_BLOCKEDON(xp)) == NONE)
	return 0;

      /* Now check if there is a cyclic dependency. For group sizes of two,  
       * a combination of SEND(REC) and RECEIVE is not fatal. Larger groups
       * or other combinations indicate a deadlock.  
       */
      if (src_dst_e == cp->p_endpoint) {	/* possible deadlock */
	  if (group_size == 2) {		/* caller and src_dst */
	      /* The function number is magically converted to flags. */
	      if ((xp->p_rts_flags ^ (function << 2)) & RTS_SENDING) { 
	          return(0);			/* not a deadlock */
	      }
	  }
#if DEBUG_ENABLE_IPC_WARNINGS
	  {
		int i;
		printf("deadlock between these processes:\n");
		for(i = 0; i < group_size; i++) {
			printf(" %10s ", processes[i]->p_name);
		}
		printf("\n\n");
		for(i = 0; i < group_size; i++) {
			print_proc(processes[i]);
			proc_stacktrace(processes[i]);
		}
	  }
#endif
          return(group_size);			/* deadlock found */
      }
  }
  return(0);					/* not a deadlock */
}

void save_context(struct proc *p){
   if(h_step == FIRST_RUN)
      save_copy_1(p);
   if(h_step == SECOND_RUN)
      save_copy_2(p);
}


int update_ws_us1_us2_data_vaddr(struct proc *rp, vir_bytes vaddr){
   int pde, pte;
   pde = I386_VM_PDE(vaddr); pte = I386_VM_PTE(vaddr);
   int r1, r2;
   struct pram_mem_block *pmb =  look_up_pte(rp, pde, pte);
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
  if(rp->p_first_step_workingset_id <= 0)
     return(OK);
  int r;
  struct pram_mem_block *pmb = rp->p_working_set;
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
     /*** Otherwise go through the working_set and search the first available
      *** bloc  ***/
		hsr_offset++;
		hsr++;
	}while(!(hsr->flags & HSR_SLOT_FREE) &&
                    hsr < END_HARDENING_SHARED_REGIONS_ADDR);

    /**The end of the working_set is reached panic **/
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
     /*** Otherwise go through the working_set and search the first available
      *** bloc  ***/
		hsp_offset++;
		hsp++;
	}while(!(hsp->flags & HSP_SLOT_FREE) &&
                    hsp < END_HARDENING_SHARED_PROCS_ADDR);

    /**The end of the working_set is reached panic **/
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

static int look_up_page_in_hsr(struct proc *rp, vir_bytes vaddr){
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

static void enable_hme_event_in_procs(struct proc *rp,  
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

static struct pram_mem_block * add_pmb(struct proc *p, phys_bytes pfa, 
      vir_bytes v, int pte){
  struct pram_mem_block *pmb, *next_pmb;
  pmb = get_pmb(); /* ask for a new pmb block in the free list*/
  assert(pmb); /* be sure that we got a good block*/
  pmb->us0 =  pfa;
  pmb->vaddr     =  v + pte * I386_PAGE_SIZE;
  if(!pfa) pmb->flags |= H_HAS_NULL_PRAM;
  /* Insert the block on the process's linked list*/
  if(!p->p_first_step_workingset_id) p->p_working_set = pmb;
  else{
    next_pmb = p->p_working_set;
    while(next_pmb->next_pmb) next_pmb = next_pmb->next_pmb; 
    next_pmb->next_pmb = pmb;
    next_pmb->next_pmb->next_pmb = NULL;
  }
  pmb->id = p->p_first_step_workingset_id;
  p->p_first_step_workingset_id++;  
  return(pmb);
}

static int check_pt_entry(u32_t pte_v){
   /* check if the page is present*/
   if(!(pte_v & I386_VM_PRESENT)) 
      return(VM_HANDLED_NO_PRESENT);
   /* Check if it is a NON USER PAGE*/
   if(!(pte_v & I386_VM_USER)) 
      return(VM_HANDLED_NO_ACESS); 
   /* Check if it is a GLOBAL_PAGE (buffer shared between os and process)*/
   if((pte_v & I386_VM_GLOBAL)) 
      return( VM_HANDLED_GLOBAL); 
   /* Check if it is a NON BIG_PAGE ( BIGPAGES are not implemented in Minix)*/
   if((pte_v & I386_VM_BIGPAGE)) 
      return(VM_HANDLED_BIG); 
   /* Check if it is a WRITE*/
   if(!(pte_v & I386_VM_WRITE)) 
      return(VM_HANDLED_NO_ACESS);
   return(OK); 
}

int inject_error_in_all_cr(struct proc *p){
   static int bit_id = 0;
   int i = 1 << (bit_id % REG_SIZE);
   u32_t cr0i = read_cr0();
   u32_t cr2i = read_cr2();
   u32_t cr3i = read_cr3();
   u32_t cr4i = read_cr4();
   if(bit_id < REG_SIZE){
      printf("Injecting in CR0 bit %d %d\n", bit_id % REG_SIZE , bit_id );
      cr0i = (cr0i&i) ? (cr0i & ~i) : cr0i | i;
      if(((bit_id % REG_SIZE)!=0) && ((bit_id % REG_SIZE)!=31) &&
         ((bit_id % REG_SIZE)!=29))
         write_cr0(cr0i);
      else
         printf("No injecting in CR0 bit %d %d\n", bit_id % REG_SIZE,
              bit_id );
   }
   
   if(bit_id >= REG_SIZE && bit_id < 2*REG_SIZE){
      printf("Injecting in CR3 bit %d %d\n", bit_id % REG_SIZE , bit_id );
      cr3i = (cr3i&i) ? (cr3i & ~i) : cr3i | i;
      if((bit_id % REG_SIZE) < 12)
         write_cr3(cr3i);
      else
         printf("No injecting in CR3 bit %d %d\n", bit_id % REG_SIZE,
              bit_id );
   
   }

   if(bit_id >= 2*REG_SIZE){
      printf("Injecting in CR4 bit %d %d\n", bit_id % REG_SIZE , bit_id );
      cr4i = (cr4i&i) ? (cr4i & ~i) : cr4i | i;
      if(((bit_id % REG_SIZE)!=4) && ((bit_id % REG_SIZE)!=5) &&
          ((bit_id % REG_SIZE)!=11) && ((bit_id % REG_SIZE)!=12) &&
          ((bit_id % REG_SIZE)<14)
         )
         write_cr4(cr4i);
      else
         printf("No injecting in CR4 bit %d %d\n", bit_id % REG_SIZE,
              bit_id );
   }
   
   if(bit_id >= 3*REG_SIZE)
     bit_id = 0;
   bit_id++;
   return(OK);
}

int inject_error_in_gpregs(struct proc *p){
  static int gpr_bit_id = 0;
   int i = 1 << (gpr_bit_id % REG_SIZE);
  if(gpr_bit_id < REG_SIZE){
      printf("Injecting in psw register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      if((gpr_bit_id % REG_SIZE)!=17)
        p->p_reg.psw = (p->p_reg.psw&i) ? (p->p_reg.psw & ~i) : p->p_reg.psw | i;
      else
        printf("No Injecting in psw register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
  }
  if((gpr_bit_id >= REG_SIZE) && (gpr_bit_id < 2*REG_SIZE)){
      printf("Injecting in ss register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.ss = (p->p_reg.ss&i) ? (p->p_reg.ss & ~i) : p->p_reg.ss | i;
  }

  if((gpr_bit_id >= 2*REG_SIZE) && (gpr_bit_id < 3*REG_SIZE)){
      printf("Injecting in sp register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
       p->p_reg.sp = (p->p_reg.sp&i) ? (p->p_reg.sp & ~i) : p->p_reg.sp | i;
  }
  if((gpr_bit_id >= 3*REG_SIZE) && (gpr_bit_id < 4*REG_SIZE)){
      printf("Injecting in cs register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.cs = (p->p_reg.cs&i) ? (p->p_reg.cs & ~i) : p->p_reg.cs | i;
  }

  if((gpr_bit_id >= 4*REG_SIZE) && (gpr_bit_id < 5*REG_SIZE)){
      printf("Injecting in di register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.di = (p->p_reg.di&i) ? (p->p_reg.di & ~i) : p->p_reg.di | i;
  }

  if((gpr_bit_id >= 5*REG_SIZE) && (gpr_bit_id < 6*REG_SIZE)){
      printf("Injecting in si register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.si = (p->p_reg.si&i) ? (p->p_reg.si & ~i) : p->p_reg.si | i;
  }

  if((gpr_bit_id >= 6*REG_SIZE) && (gpr_bit_id < 7*REG_SIZE)){
      printf("Injecting in fp register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.fp = (p->p_reg.fp&i) ? (p->p_reg.fp & ~i) : p->p_reg.fp | i;
  }

  if((gpr_bit_id >= 7*REG_SIZE) && (gpr_bit_id < 8*REG_SIZE)){
      printf("Injecting in bx register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.bx = (p->p_reg.bx&i) ? (p->p_reg.bx & ~i) : p->p_reg.bx | i;
  }

  if((gpr_bit_id >= 8*REG_SIZE) && (gpr_bit_id < 9*REG_SIZE)){
      printf("Injecting in dx register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.dx = (p->p_reg.dx&i) ? (p->p_reg.dx & ~i) : p->p_reg.dx | i;
  }

  if((gpr_bit_id >= 9*REG_SIZE) && (gpr_bit_id < 10*REG_SIZE)){
      printf("Injecting in cx register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.cx = (p->p_reg.cx&i) ? (p->p_reg.cx & ~i) : p->p_reg.cx | i;
  }

  if((gpr_bit_id >= 10*REG_SIZE) && (gpr_bit_id < 11*REG_SIZE)){
      printf("Injecting in retreg register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.retreg = (p->p_reg.retreg&i) ? (p->p_reg.retreg & ~i) : p->p_reg.retreg | i;
  }

  if((gpr_bit_id >= 11*REG_SIZE) && (gpr_bit_id < 12*REG_SIZE)){
      printf("Injecting in pc register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.pc = (p->p_reg.pc&i) ? (p->p_reg.pc & ~i) : p->p_reg.pc | i;
  }
 
  if((gpr_bit_id >= 12*REG_SIZE) && (gpr_bit_id < 13*REG_SIZE)){
      printf("Injecting in ds register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.ds = (p->p_reg.ds&i) ? (p->p_reg.ds & ~i) : p->p_reg.ds | i;
  }

  if((gpr_bit_id >= 13*REG_SIZE) && (gpr_bit_id < 14*REG_SIZE)){
      printf("Injecting in es register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
     p->p_reg.es = (p->p_reg.es&i) ? (p->p_reg.es & ~i) : p->p_reg.es | i;
  }

  if((gpr_bit_id >= 14*REG_SIZE) && (gpr_bit_id < 15*REG_SIZE)){
      printf("Injecting in fs register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.fs = (p->p_reg.fs&i) ? (p->p_reg.fs & ~i) : p->p_reg.fs | i;
  }

  if((gpr_bit_id >= 15*REG_SIZE) && (gpr_bit_id < 16*REG_SIZE)){
      printf("Injecting in gs register bit %d %d\n", 
                      gpr_bit_id % REG_SIZE , gpr_bit_id );
      p->p_reg.gs = (p->p_reg.gs&i) ? (p->p_reg.gs & ~i) : p->p_reg.gs | i;
  }
  gpr_bit_id++;
  if(gpr_bit_id >= 16*REG_SIZE)
     gpr_bit_id = 0;
  return(OK);
}

static void restore_cr_reg(void){
  write_cr0(cr0);
  write_cr3(cr3);
  write_cr4(cr4);
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
      pmb->flags |= H_TO_UPDATE;
       
    }
#if H_DEBUG
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
  if(!p->p_first_step_workingset_id) 
      p->p_working_set = pmb;
  else{
    next_pmb = p->p_working_set;
    while(next_pmb->next_pmb) 
       next_pmb = next_pmb->next_pmb; 
    next_pmb->next_pmb = pmb;
    next_pmb->next_pmb->next_pmb = NULL;
  }
  pmb->id = p->p_first_step_workingset_id;
  p->p_first_step_workingset_id++;  
  return(pmb);
}


int set_pe_mem_to_ro(struct proc *p, u32_t *root){
   int pte, pde;
   u32_t pde_v, pte_v, pfa; // pde entry value
   u32_t *pte_a; // page table address
   if(p->p_first_step_workingset_id <= 0)
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
   struct pram_mem_block *pmb = p->p_working_set;
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
