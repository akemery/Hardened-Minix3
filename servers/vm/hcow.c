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
