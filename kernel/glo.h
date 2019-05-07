#ifndef GLO_H
#define GLO_H

/* Global variables used in the kernel. This file contains the declarations;
 * storage space for the variables is allocated in table.c, because EXTERN is
 * defined as extern unless the _TABLE definition is seen. We rely on the 
 * compiler's default initialization (0) for several global variables. 
 */
#ifdef _TABLE
#undef EXTERN
#define EXTERN
#endif

#include <minix/config.h>
#include <minix/ipcconst.h>
#include <machine/archtypes.h>
#include "archconst.h"
#include "config.h"
#include "debug.h"

/* Kernel information structures. This groups vital kernel information. */
extern struct kinfo kinfo;		  /* kernel information for services */
extern struct machine machine;		  /* machine info for services */
extern struct kmessages kmessages;  	  /* diagnostic messages in kernel */
extern struct loadinfo loadinfo;	  /* status of load average */
extern struct kuserinfo kuserinfo;	  /* kernel information for users */
extern struct arm_frclock arm_frclock;	  /* ARM free-running timer info */
extern struct kclockinfo kclockinfo;	  /* clock information */
extern struct minix_kerninfo minix_kerninfo;

EXTERN struct k_randomness krandom; 	/* gather kernel random information */

EXTERN vir_bytes minix_kerninfo_user;

#define kmess kmessages
#define kloadinfo loadinfo

#define system_hz (kclockinfo.hz)		/* HZ value (alias) */

/* Process scheduling information and the kernel reentry count. */
EXTERN struct proc *vmrequest;  /* first process on vmrequest queue */
EXTERN unsigned lost_ticks;	/* clock ticks counted outside clock task */
EXTERN char *ipc_call_names[IPCNO_HIGHEST+1]; /* human-readable call names */
EXTERN struct proc *kbill_kcall; /* process that made kernel call */
EXTERN struct proc *kbill_ipc; /* process that invoked ipc */

/* Interrupt related variables. */
EXTERN irq_hook_t irq_hooks[NR_IRQ_HOOKS];	/* hooks for general use */
EXTERN int irq_actids[NR_IRQ_VECTORS];		/* IRQ ID bits active */
EXTERN int irq_use;				/* map of all in-use irq's */

/* Miscellaneous. */
EXTERN int verboseboot;			/* verbose boot, init'ed in cstart */

#if DEBUG_TRACE
EXTERN int verboseflags;
#endif

#ifdef USE_APIC
EXTERN int config_no_apic; /* optionally turn off apic */
EXTERN int config_apic_timer_x; /* apic timer slowdown factor */
#endif

EXTERN u64_t cpu_hz[CONFIG_MAX_CPUS];

#define cpu_set_freq(cpu, freq)	do {cpu_hz[cpu] = freq;} while (0)
#define cpu_get_freq(cpu)	cpu_hz[cpu]

#ifdef CONFIG_SMP
EXTERN int config_no_smp; /* optionally turn off SMP */
#endif

/* VM */
EXTERN int vm_running;
EXTERN int catch_pagefaults;
EXTERN int kernel_may_alloc;

/* Variables that are initialized elsewhere are just extern here. */
extern struct boot_image image[NR_BOOT_PROCS]; 	/* system image processes */

EXTERN volatile int serial_debug_active;

EXTERN struct cpu_info cpu_info[CONFIG_MAX_CPUS];

/* BKL stats */
EXTERN u64_t kernel_ticks[CONFIG_MAX_CPUS];
EXTERN u64_t bkl_ticks[CONFIG_MAX_CPUS];
EXTERN unsigned bkl_tries[CONFIG_MAX_CPUS];
EXTERN unsigned bkl_succ[CONFIG_MAX_CPUS];

/* Feature flags */
EXTERN int minix_feature_flags;

/**hardening data**/
EXTERN u16_t gs_1;
EXTERN u16_t fs_1;
EXTERN u16_t es_1;
EXTERN u16_t ds_1;
EXTERN reg_t di_1;
EXTERN reg_t si_1;
EXTERN reg_t fp_1;
EXTERN reg_t st_1;
EXTERN reg_t bx_1;
EXTERN reg_t dx_1;
EXTERN reg_t cx_1;
EXTERN reg_t retreg_1;
EXTERN reg_t retadr_1;
EXTERN reg_t pc_1;
EXTERN reg_t cs_1;
EXTERN reg_t psw_1;
EXTERN reg_t sp_1;
EXTERN reg_t ss_1;
EXTERN vir_bytes delivermsg_vir_1;
EXTERN struct stackframe_s p_reg_1;	
EXTERN struct segframe p_seg_1;	
EXTERN u32_t p_rts_flags_1;	
EXTERN u32_t p_misc_flags_1;	
EXTERN  char p_priority_1;		
EXTERN u64_t p_cpu_time_left_1;	
EXTERN unsigned p_quantum_size_ms_1;	
EXTERN u64_t p_cycles_1;		
EXTERN u64_t p_kcall_cycles_1;		
EXTERN u64_t p_kipc_cycles_1;		
EXTERN endpoint_t p_getfrom_e_1;	
EXTERN endpoint_t p_sendto_e_1;	
EXTERN sigset_t p_pending_1;		
EXTERN message p_sendmsg_1;		
EXTERN message p_delivermsg_1;		
EXTERN vir_bytes p_delivermsg_vir_1;	
EXTERN int p_found_1;	
EXTERN int p_magic_1;		
EXTERN reg_t r1_1, r2_1, r3_1;
EXTERN int	p_kern_trap_style_1;
EXTERN u32_t p_cr3_1;
EXTERN u32_t p_cr3_v_1;

EXTERN u16_t gs_2;
EXTERN u16_t fs_2;
EXTERN u16_t es_2;
EXTERN u16_t ds_2;
EXTERN reg_t di_2;
EXTERN reg_t si_2;
EXTERN reg_t fp_2;
EXTERN reg_t st_2;
EXTERN reg_t bx_2;
EXTERN reg_t dx_2;
EXTERN reg_t cx_2;
EXTERN reg_t retreg_2;
EXTERN reg_t retadr_2;
EXTERN reg_t pc_2;
EXTERN reg_t cs_2;
EXTERN reg_t psw_2;
EXTERN reg_t sp_2;
EXTERN reg_t ss_2;
EXTERN vir_bytes delivermsg_vir_2;
EXTERN struct stackframe_s p_reg_2;	
EXTERN struct segframe p_seg_2;	
EXTERN  u32_t p_rts_flags_2;	
EXTERN  u32_t p_misc_flags_2;	
EXTERN  char p_priority_2;		
EXTERN u64_t p_cpu_time_left_2;	
EXTERN unsigned p_quantum_size_ms_2;	
EXTERN u64_t p_cycles_2;		
EXTERN u64_t p_kcall_cycles_2;		
EXTERN u64_t p_kipc_cycles_2;		
EXTERN endpoint_t p_getfrom_e_2;	
EXTERN endpoint_t p_sendto_e_2;	
EXTERN sigset_t p_pending_2;		
EXTERN message p_sendmsg_2;		
EXTERN message p_delivermsg_2;		
EXTERN vir_bytes p_delivermsg_vir_2;	
EXTERN int p_found_2;	
EXTERN int p_magic_2;		
EXTERN reg_t r1_2, r2_2, r3_2;
EXTERN int	p_kern_trap_style_2;
EXTERN u32_t p_cr3_2;
EXTERN u32_t p_cr3_v_2;

/*start proc data to save*/
EXTERN struct stackframe_s p_reg_back;	
EXTERN struct segframe p_seg_back;	
EXTERN  char p_priority_back;		
EXTERN u64_t p_cpu_time_left_back;	
EXTERN unsigned p_quantum_size_ms_back;	
EXTERN u64_t p_cycles_back;		
EXTERN u64_t p_kcall_cycles_back;		
EXTERN u64_t p_kipc_cycles_back;		
EXTERN endpoint_t p_getfrom_e_back;	
EXTERN endpoint_t p_sendto_e_back;	
EXTERN sigset_t p_pending_back;		
EXTERN message p_sendmsg_back;		
EXTERN message p_delivermsg_back;		
EXTERN vir_bytes p_delivermsg_vir_back;	
EXTERN int p_found_back;	
EXTERN int p_magic_back;		
EXTERN reg_t r1, r2, r3;
EXTERN int	p_kern_trap_style;
EXTERN u32_t p_rts_flags;
EXTERN u32_t p_cr3;
EXTERN u32_t p_cr3_v;
EXTERN u16_t gs;
EXTERN u16_t fs;
EXTERN u16_t es;
EXTERN u16_t ds;
EXTERN reg_t di;
EXTERN reg_t si;
EXTERN reg_t fp;
EXTERN reg_t st;
EXTERN reg_t bx;
EXTERN reg_t dx;
EXTERN reg_t cx;
EXTERN reg_t retreg;
EXTERN reg_t retadr;
EXTERN reg_t pc;
EXTERN reg_t cs;
EXTERN reg_t psw;
EXTERN reg_t sp;
EXTERN reg_t ss;

/**hardening data**/
EXTERN reg_t eax_s;
EXTERN reg_t ebx_s;
EXTERN reg_t ecx_s;
EXTERN reg_t edx_s;
EXTERN reg_t esi_s;
EXTERN reg_t edi_s;
EXTERN reg_t esp_s;
EXTERN reg_t ebp_s;
EXTERN int origin_syscall;
EXTERN int h_normal_pf;
EXTERN int h_pf_handle_by_k;
EXTERN  int h_rw ;
EXTERN int h_stop_pe;

EXTERN reg_t eax_s1;
EXTERN reg_t ebx_s1;
EXTERN reg_t ecx_s1;
EXTERN reg_t edx_s1;
EXTERN reg_t esi_s1;
EXTERN reg_t edi_s1;
EXTERN reg_t esp_s1;
EXTERN reg_t ebp_s1;

EXTERN reg_t eax_s2;
EXTERN reg_t ebx_s2;
EXTERN reg_t ecx_s2;
EXTERN reg_t edx_s2;
EXTERN reg_t esi_s2;
EXTERN reg_t edi_s2;
EXTERN reg_t esp_s2;
EXTERN reg_t ebp_s2;

EXTERN int h_enable;      /*  used to enable the hardening  */
EXTERN int h_step;        /** used to store the hardening step 1 or step 2**/
EXTERN int h_proc_nr;     /** current proc in the hardening process **/
EXTERN int h_step_back;
EXTERN int h_do_sys_call;   /* remember that the process do a sys_call */
EXTERN int h_do_nmi;        /* remember an NMI event */
EXTERN int hprocs_in_use;  /* #process in the system */
EXTERN int vm_should_run;   /* VM should run */
EXTERN int pe_should_run;
EXTERN int h_restore;
EXTERN int h_vm_end_h_req;
EXTERN int from_exec;
EXTERN int proc_2_delay;
EXTERN int h_restore_after_kill;
EXTERN int h_wait_vm_reply;
/** That means the system is in unstable state
 ** because the comparison stage failed.
 ** The solution is to cancel all thing that fault
 ** trigger in the system. The main objective is to
 ** keep the effect of that event in the kernel.
 ** it should certainly not be spread to the rest of the system**/
EXTERN int h_unstable_state; 


EXTERN int origin_1;
EXTERN int origin_2;
EXTERN vir_bytes pagefault_addr_1;
EXTERN vir_bytes pagefault_addr_2;

EXTERN u32_t cr0;
EXTERN u32_t cr2;
EXTERN u32_t cr3;
EXTERN u32_t cr4;

EXTERN u32_t cr0_1;
EXTERN u32_t cr0_2;
EXTERN u32_t cr2_1;
EXTERN u32_t cr2_2;
EXTERN u32_t cr3_1;
EXTERN u32_t cr3_2;
EXTERN u32_t cr4_1;
EXTERN u32_t cr4_2;

/** Injection period based on number of processing element**/

EXTERN int id_last_inject_pe;
EXTERN int id_current_pe;
EXTERN int could_inject; /**could inject fault when start first or second run**/
EXTERN int h_can_start_hardening;


EXTERN struct hardening_shared_region *all_hsr_s;
EXTERN struct hardening_shared_proc   *all_hsp_s;
EXTERN int n_hsps;
EXTERN int n_hsrs;
#endif /* GLO_H */
