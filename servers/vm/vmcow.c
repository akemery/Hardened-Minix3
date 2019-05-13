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
static int hmap_pf(struct vmproc *vmp, struct vir_region *region,
          vir_bytes offset, int write, u32_t addr, int rw, int what);
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
        if(!vmp->vm_lus1_us2_size)
            vmp->vm_lus1_us2 = pmb;
        else{
             next_pmb = vmp->vm_lus1_us2;
             while(next_pmb->next_pmb) next_pmb = next_pmb->next_pmb; 
             next_pmb->next_pmb = pmb;
             next_pmb->next_pmb->next_pmb = NULL;
        }
        pmb->id = vmp->vm_lus1_us2_size;
        vmp->vm_lus1_us2_size++; 
  
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

/*===========================================================================*
 *				do_hpagefaults	     		     *
 *===========================================================================*/
void do_hpagefaults(message *m)
{
	endpoint_t ep = m->m_source;
	u32_t addr = m->VPF_ADDR;
	u32_t err = m->VPF_FLAGS;
	struct vmproc *vmp;
	int s, mem_flags = 0;

	struct vir_region *region;
	vir_bytes offset;
	int p, wr = PFERR_WRITE(err), rw = 0, what = 0;

	if(vm_isokendpt(ep, &p) != OK)
	   panic("do_pagefaults: endpoint wrong: %d", ep);

	vmp = &vmproc[p];
	assert((vmp->vm_flags & VMF_INUSE));
        
        /* 1st execution*/
        if(m->m_type == VM_HR1PAGEFAULT )
             what = VM_FIRST_RUN;
 
        /* 2nd execution */
        if(m->m_type == VM_HR2PAGEFAULT)
             what = VM_SECOND_RUN; 

        /* The virtual address is not belong a valid memory space */
	if(!(region = map_lookup(vmp, addr, NULL))) {
                panic("region null 0x%x\n", addr);
	}
	assert(region);
	assert(addr >= region->vaddr);
	offset = addr - region->vaddr;
      
	   /* Access is allowed; handle it. allocate the frame */
        if((hmap_pf(vmp, region, offset, wr,addr, rw, what)) != OK) {
		printf("VM: pagefault: SIGSEGV %d pagefault not handled\n", ep);
		if((s=sys_kill(vmp->vm_endpoint, SIGSEGV)) != OK)
			panic("sys_kill failed: %d", s);
		if((s=sys_vmctl(ep, VMCTL_CLEAR_PAGEFAULT, 0 /*unused*/)) != OK)
			panic("do_pagefaults: sys_vmctl failed: %d", ep);
		return;
	}
     
	/* Pagefault is handled, so now reactivate the process. */
	if((s=sys_vmctl(ep, VMCTL_CLEAR_PAGEFAULT, 0 /*unused*/)) != OK)
		panic("do_pagefaults: sys_vmctl failed: %d", ep);
       
}

/*===========================================================================*
 *				hmap_pf			     *
 *===========================================================================*/
static int hmap_pf(vmp, region, offset, write, addr, rw, what)
struct vmproc *vmp;
struct vir_region *region;
vir_bytes offset;
int write;
u32_t addr;
int rw;
int what;
{
	struct phys_region *ph;
	int r = OK;
	struct phys_block *pb;
        
	offset -= offset % VM_PAGE_SIZE;

	assert(offset >= 0);
	assert(offset < region->length);

	assert(!(region->vaddr % VM_PAGE_SIZE));
	assert(!(write && !(region->flags & VR_WRITABLE)));

        
        /* get the phys block in the VM.
           Phys block is the data structure to handle the page in the VM*/
    
        ph = physblock_get(region, offset);

        assert(ph);
        

        /**Do the allocation of US1 or US2 frame**/
        allocate_mem_4_hardening(vmp, region, ph, what);
        return(OK);
}

int do_memconf(message *m){

        endpoint_t ep = m->m_source;
	struct vmproc *vmp;
	int p;

	if(vm_isokendpt(ep, &p) != OK)
	   panic("do_pagefaults: endpoint wrong: %d", ep);

	vmp = &vmproc[p];
        free_pram_mem_blocks(vmp);   
        return(OK);
      
}

