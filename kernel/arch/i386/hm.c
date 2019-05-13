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
static void init_hardening_features(void);

static void init_hardening_features(void){
#if USE_MCA
   enables_all_mca_features();
   enable_loggin_ofall_errors();
   clears_all_errors();
   enable_machine_check_exception();
#endif

#if USE_INS_COUNTER
#if USE_FIX_CTR
	intel_fixed_insn_counter_init();
#else
	intel_arch_insn_counter_init();
#endif
#endif
 
}

void init_hardening(void){
  struct pram_mem_block *pmb;
  struct hardening_mem_event *hme;
  struct hardening_shared_region *hsr;
  struct hardening_shared_proc *hsp;
  int i;
  int h_enable = 0;
  int h_proc_nr = 0;
  int h_do_sys_call = 0;
  int h_do_nmi = 0;
  int hprocs_in_use = 0;
  int h_step = 0;
  int h_step_back = 0;
  int vm_should_run = 0;
  int pe_should_run = 0;
  int h_restore = 0;
  int h_vm_end_h_req = 0;
  int from_exec = 0;
  int proc_2_delay = 0;
  int h_unstable_state = 0;
  int id_last_inject_pe   = 0;
  int id_current_pe = 0;
  int h_wait_vm_reply = H_NO;
  vir_bytes pagefault_addr_1 = 0;
  vir_bytes pagefault_addr_2 = 0;
  struct hardening_shared_region *all_hsr_s = NULL;
  struct hardening_shared_proc   *all_hsp_s = NULL;
  h_can_start_hardening = 0;
  int n_hsps = 0;
  int n_hsrs = 0;
  u32_t cr0 = 0;
  u32_t cr2 = 0;
  u32_t cr3 = 0;
  u32_t cr4 = 0;
  u32_t cr0_1 = 0;
  u32_t cr0_2 = 0;
  u32_t cr2_1 = 0;
  u32_t cr2_2 = 0;
  u32_t cr3_1 = 0;
  u32_t cr3_2 = 0;
  u32_t cr4_1 = 0;
  u32_t cr4_2 = 0;
  u32_t first_run_ins = 0;
  u32_t secnd_run_ins = 0;
  int h_exception = 0;
  int nbpe = 0;
  int nbpe_f = 0;
  for(i=0; i<10; i++)
    hc_proc_nr[i] = 0;
  for(pmb = BEG_PRAM_MEM_BLOCK_ADDR;
    pmb < END_PRAM_MEM_BLOCK_ADDR; pmb++){
             pmb->flags = PRAM_SLOT_FREE;
             pmb->vaddr = 0;
             pmb->id = 0;
             pmb->us0 = 0;
             pmb->us1 = 0;
             pmb->us2 = 0;
             pmb->next_pmb = NULL;
        }

  for(hme = BEG_HARDENING_MEM_EVENTS_ADDR; 
       hme < END_HARDENING_MEM_EVENTS_ADDR; hme++){
             hme->flags = HME_SLOT_FREE;
             hme->addr_base = 0;
             hme->nbytes = 0;
             hme->id = 0;
             hme->npages = 0;
             hme->next_hme = NULL;
        }

  for(hsr = BEG_HARDENING_SHARED_REGIONS_ADDR; 
     hsr < END_HARDENING_SHARED_REGIONS_ADDR; hsr++){ 
            hsr->id = 0;
            hsr->flags = HSR_SLOT_FREE;
            hsr->r_id = 0;
            hsr->vaddr = 0;
            hsr->length = 0;
            hsr->next_hsr = NULL;
            hsr->r_hsp = NULL;   
            hsr->n_hsp = 0;
        }

  for(hsp = BEG_HARDENING_SHARED_PROCS_ADDR; 
       hsp < END_HARDENING_SHARED_PROCS_ADDR; hsp++){
            hsp->hsp_endpoint = 0;
            hsp->flags = HSP_SLOT_FREE;
            hsp->id = 0;
            hsp->next_hsp = NULL;
       }

}
