
#ifndef _VMPROC_H 
#define _VMPROC_H 1

#include <minix/bitmap.h>
#include <machine/archtypes.h>

#include "pt.h"
#include "vm.h"
#include "regionavl.h"
#include "htype.h"

struct vmproc;

struct vmproc {
	int		vm_flags;
	endpoint_t	vm_endpoint;
	pt_t		vm_pt;	/* page table data */
	struct boot_image *vm_boot; /* if boot time process */

	/* Regions in virtual address space. */
	region_avl vm_regions_avl;
	vir_bytes  vm_region_top;	/* highest vaddr last inserted */
	int vm_acl;
	int vm_slot;		/* process table slot */
#if VMSTATS
	int vm_bytecopies;
#endif
	vir_bytes	vm_total;
	vir_bytes	vm_total_max;
	u64_t		vm_minor_page_fault;
	u64_t		vm_major_page_fault;
#if 1
  /*structure pour maintenir la liste des pages dans le working set*/
  struct pram_mem_block *vm_lus1_us2;
  int vm_lus1_us2_size;
  int vm_hflags; 
#endif
};

/* Bits for vm_flags */
#define VMF_INUSE	0x001	/* slot contains a process */
#define VMF_EXITING	0x002	/* PM is cleaning up this process */
#define VMF_VM_INSTANCE 0x010   /* This is a VM process instance */

#endif
