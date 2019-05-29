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
static void vm_resetmem(struct proc *p, u32_t *pagetable, const u32_t v);
static int deadlock(int function, register struct proc *cp, endpoint_t src_dst_e);
static void restore_cr_reg(void);
static void print_rdyqueue(void);
static void print_ipc(struct proc *p);

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

/*===========================================================================*
 *				sendmsg2vm              	             *
 *===========================================================================*/
int sendmsg2vm(struct proc * pr){
     message m;
     int err;
     m.m_source = pr->p_endpoint;
    // m.m_type   = VM_HCONFMEM;
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

void display_hardened_proc(void){
   struct proc *rp;
   for (rp = BEG_PROC_ADDR; rp < END_PROC_ADDR; ++rp) {
       if(rp->p_hflags & PROC_TO_HARD)
           print_proc(rp);		
  }
  print_rdyqueue();
}

void reset_hardening_attri(struct proc *p){
   p->p_hflags = 0;
   p->p_lus1_us2 = NULL;
   p->p_lus1_us2_size = 0; 
   p->p_workingset_size = 0;
   p->p_remaining_ins = 0; /*remain instructions*/
   p->p_ins_first = 0;
   p->p_ins_secnd = 0;
   p->p_ins_last = 0;
   p->p_start_count_ins = 0;
   p->p_hardening_mem_events = NULL;
   p->p_nb_hardening_mem_events = 0;
   p->p_hardening_shared_regions = NULL;
   p->p_nb_hardening_shared_regions = 0;
}

static void print_rdyqueue(void){
  int q,i;
  register struct proc *rp;			
  struct proc **rdy_head;
  rdy_head = get_cpulocal_var(run_q_head);
  printf("#### PRINTING READY QUEUE ######\n\n");
  for (q=0; q < NR_SCHED_QUEUES; q++) { 
     if(!(rp = rdy_head[q])) 
       continue; 
     printf("h_enable %d queue %d proc %d name %s hproc %d\n"
                     ,h_enable, q, rp->p_nr, rp->p_name, h_proc_nr);
  }
  for(i=0; i<10; i++){
     if(hc_proc_nr[i]){
           if(proc_addr(hc_proc_nr[i])->p_rts_flags == 1) continue;
           printf("@@@@@@ hproc: %s %d %d  sendto %d getfrom %d vm %d vfs %d pm %d"
                   "vm_sendto %d vmgetfrom %d pmsento %d pmgetfrom %d"
                   "vfssento %d vfsgetfrom %d %d\n", 
              proc_addr(hc_proc_nr[i])->p_name, proc_addr(hc_proc_nr[i])->p_nr, 
              proc_addr(hc_proc_nr[i])->p_rts_flags,
              proc_addr(hc_proc_nr[i])->p_sendto_e,
              proc_addr(hc_proc_nr[i])->p_getfrom_e,
              proc_addr(VM_PROC_NR)->p_rts_flags,
              proc_addr(VFS_PROC_NR)->p_rts_flags,
              proc_addr(PM_PROC_NR)->p_rts_flags,
              proc_addr(VM_PROC_NR)->p_sendto_e,
              proc_addr(VM_PROC_NR)->p_getfrom_e,
              proc_addr(PM_PROC_NR)->p_sendto_e,
              proc_addr(PM_PROC_NR)->p_getfrom_e,
              proc_addr(VFS_PROC_NR)->p_sendto_e,
              proc_addr(VFS_PROC_NR)->p_getfrom_e,i);
              print_ipc(proc_addr(hc_proc_nr[i]));
              print_ipc(proc_addr(VM_PROC_NR));
              print_ipc(proc_addr(PM_PROC_NR));
              print_ipc(proc_addr(VFS_PROC_NR));
         
      }
  }
  return;
}

static void print_ipc(struct proc *p){
     struct proc *q =  p->p_caller_q;
     printf("### Queue of %s\n", p->p_name);
     while(q){
        printf("@@@@@@ proc: %s %d %d  sendto %d getfrom %d\n",
          q->p_name, q->p_nr, q->p_rts_flags, q->p_sendto_e, q->p_getfrom_e);
        q = q->p_q_link;
     }
}
