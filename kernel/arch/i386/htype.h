#ifndef HTYPE_H
#define HTYPE_H

/**Here are defined the data structure for the hardening module
 ** in the micro-kernel
 ** -- pram_mem_blocks
 ** Author: Emery Kouassi Assogba
 ** Email: assogba.emery@gmail.com
 ** Phone: 0022995222073
 ** 22/01/2019 lln**/

#include <minix/const.h>
#include <sys/cdefs.h>

#ifndef __ASSEMBLY__

#include <minix/com.h>
#include <minix/portio.h>

/** pram_mem_block is the data structure to capture the handling of the
 ** copy-on-write in the micro-kernel
 ** id : is the number to identifie the memory bloc if the working set
 **   block id to allow the micro-kernel to be consistent with VM
 ** flags: is used to capture the state of the memory block
 ** vaddr: is the virtual addresse of the page where the page fault occurs
 ** ram_phys: is the current frame used for the page in  copy-on-write 
 ** us0: is the backup frame used for the page in  copy-on-write 
 ** us1: is the frame used during first run by 
 **       the page in  copy-on-write 
 ** us2: is the frame used during first run by 
 **       the page in  copy-on-write  **/
struct pram_mem_block {
 int                       id; 
 int                       flags;
 int                       iflags; 
 vir_bytes                 vaddr;  
 phys_bytes                us0; 
 phys_bytes                us1; 
 phys_bytes                us2; 
 struct pram_mem_block *next_pmb;
};

struct hardening_mem_event {
 int id;
 int flags;
 vir_bytes addr_base;
 vir_bytes nbytes;
 int npages;
 struct hardening_mem_event *next_hme;
};

struct hardening_shared_proc{
  endpoint_t hsp_endpoint;
  int flags;
  int id;
  struct hardening_shared_proc *next_hsp;
};

struct hardening_shared_region{
   int id;
   int flags;
   int r_id;
   vir_bytes vaddr;
   vir_bytes length;
   struct hardening_shared_region *next_hsr;
   struct hardening_shared_proc *r_hsp;   
   int n_hsp;
};

#define MAP_NONE	0xFFFFFFFE
#define WORKING_SET_SIZE      32768
#define HARDENING_MEM_EVENTS  10000 
#define HARDENING_SHARED_REGIONS 50
#define HARDENING_SHARED_PROCS  100
#define H_DISABLE              0
#define H_ENABLE               1
#define HME_SLOT_FREE          1 
#define PRAM_SLOT_FREE         1
#define HSR_SLOT_FREE          1
#define HSP_SLOT_FREE          1
#define RESTORE_FOR_SECOND_RUN 1
#define RESTORE_FOR_FISRT_RUN  2
#define NO_HARD_RUN            0
#define FIRST_RUN              1
#define SECOND_RUN             2
#define VM_RUN                 3
#define FIRST_STEPPING         4
#define H_STEPPING             4        
#define H_YES                  1
#define H_NO                   0
#define VM_HANDLED_PF         -1
#define VM_HANDLED_PF_ABS_WS  -2
#define VM_HANDLED_NO_ACESS   -3
#define VM_HANDLED_NO_PRESENT -4
#define VM_HANDLED_PFA_NULL   -5
#define VM_VADDR_NOT_FOUND    -6
#define PROC_NOT_SHARING      -7
#define VM_HANDLED_GLOBAL     -8
#define VM_HANDLED_BIG        -9
#define N_OK                 -10
#define RO_PAGE_FIRST_RUN      1
#define RO_PAGE_SECOND_RUN     2
#define RW_PAGE_FIRST_RUN      3
#define RW_PAGE_SECOND_RUN     4
#define TELL_VM_NORMAL_PF      5
#define K_HANDLE_PF            6
#define TELL_VM_PAGE_ABS       7   
#define NORMAL_PF              1
#define PRAM_LAST_PF           2
#define PRAM_LAST_NPF          4
#define HGET_PF           0x2000
#define IWS_PF_FIRST      0x4000
#define IWS_PF_SECOND     0x8000
#define IWS_MOD_KERNEL   0x10000
#define FWS              0x20000
#define WS_SHARED        0x40000
#define RTS_STOP_4_PF    0x40000
#define H_HAS_NULL_PRAM  0x80000
#define H_TO_UPDATE     0x100000
#define H_FORK          0x200000
#define H_EXEC          0x400000
#define NO_REGION_PAGE      0x10
#define CPY_RAM_FIRST          0
#define CPY_RAM_SECOND       0x1
#define CPY_RAM_PRAM         0x2
#define CMP_FAILED           0x3
#define CPY_RAM_FIRST_STEPPING 0x8
#define ABORT_PE            0x10
#define PROC_TO_HARD         0x2
#define PROC_SHARING_MEM     0x4
#define SHARED_ADDR   0xf100205c
#define H_STABLE               0
#define H_UNSTABLE             1
#define H_INCORRECTION         2
#define H_PERIOD_TO_INJECT    10
#define H_THRESHOLD_PE     65300
#define INJECT_FAULT           0
#define H_PAGE_FAULT           6
#define REG_SIZE              32
#define FROM_EXEC           0x10
#define PE_END_IN_NMI          7
#define I386_VM_ADDR_MASK_INV  0x00000FFF


#define BEG_PRAM_MEM_BLOCK_ADDR (&working_set[0])
#define END_PRAM_MEM_BLOCK_ADDR (&working_set[WORKING_SET_SIZE -1])

#define BEG_HARDENING_MEM_EVENTS_ADDR (&hardening_mem_events[0])
#define END_HARDENING_MEM_EVENTS_ADDR \
        (&hardening_mem_events[HARDENING_MEM_EVENTS -1])

#define BEG_HARDENING_SHARED_REGIONS_ADDR (&hardening_shared_regions[0])
#define END_HARDENING_SHARED_REGIONS_ADDR \
        (&hardening_shared_regions[HARDENING_SHARED_REGIONS -1])

#define BEG_HARDENING_SHARED_PROCS_ADDR (&hardening_shared_procs[0])
#define END_HARDENING_SHARED_PROCS_ADDR \
        (&hardening_shared_procs[HARDENING_SHARED_PROCS -1])

#endif /* __ASSEMBLY__ */

#ifndef __ASSEMBLY__
/*table to store the modified process pages*/
struct pram_mem_block working_set[WORKING_SET_SIZE];
struct hardening_mem_event hardening_mem_events[HARDENING_MEM_EVENTS];
struct hardening_shared_region hardening_shared_regions[HARDENING_SHARED_REGIONS];
struct hardening_shared_proc hardening_shared_procs[HARDENING_SHARED_PROCS];



#endif /* __ASSEMBLY__ */

#endif /* HTYPE_H */


