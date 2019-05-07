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
 vir_bytes                 vaddr; 
 phys_bytes                us0; 
 phys_bytes                us1; 
 phys_bytes                us2; 
 struct pram_mem_block *next_pmb;
};

#define WORKING_SET_SIZE     32768
#define P_WRITABLE             1
#define VM_FIRST_RUN           1
#define VM_SECOND_RUN          2
#define PRAM_RW_PAGE          16
#define PRAM_SLOT_FREE         1
#define NO_REGION_PAGE      0x10
#define VM_PROC_TO_HARD      0x4

#define BEG_PRAM_MEM_BLOCK_ADDR (&working_set[0])
#define END_PRAM_MEM_BLOCK_ADDR (&working_set[WORKING_SET_SIZE -1])

#endif /* __ASSEMBLY__ */

#ifndef __ASSEMBLY__
/*table to store the modified process pages*/
struct pram_mem_block working_set[WORKING_SET_SIZE];


#endif /* __ASSEMBLY__ */

#endif /* HTYPE_H */
