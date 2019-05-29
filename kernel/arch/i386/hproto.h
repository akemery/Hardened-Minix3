/* Function prototypes. */

#ifndef HPROTO_H
#define HPROTO_H

u32_t phys_get32(phys_bytes v);
int phys_set32(phys_bytes addr, u32_t *v);
void vm_setpt_root_to_ro(struct proc *p, u32_t *root);
void vm_reset_pram(struct proc *p, u32_t *root, int endcmp);
void free_pram_mem_blocks(struct proc *current_p, int no_msg_to_vm);
void vm_resetmem_pt_root_to_ro(struct proc *p, u32_t *root);
int cmp_frames(u32_t frame1, u32_t frame2);
int cpy_frames(u32_t src, u32_t dst);
void display_mem(struct proc *current_p);
int sendmsg2vm(struct proc * pr);
void free_pram_mem_block(struct proc *current_p, 
                       vir_bytes vaddr, u32_t *root);
struct pram_mem_block * look_up_lastpf_pte(struct proc *current_p, int normal);
int update_all_ws_us1_us2_data(struct proc *rp);
int update_ws_us1_us2_data_vaddr(struct proc *rp, vir_bytes vaddr);
int update_range_ws_us1_us2_data(struct proc *rp, vir_bytes offset,
             int n_pages_covered);

void free_hardening_mem_events(struct proc *rp);
int  handle_hme_events(struct proc *rp);
int add_hme_event(struct proc *rp, vir_bytes offset, vir_bytes size);
struct hardening_mem_event * look_up_hme(struct proc *rp, vir_bytes offset);

void  handle_hsr_events(struct proc *rp);
void free_hsrs(struct proc *rp);
int add_hsr(struct proc *rp, vir_bytes offset, vir_bytes size, int r_id);

int add_hsp(struct proc *rp, struct hardening_shared_region *hsr);
void display_all_hsp_s(void);
void display_all_hsr_s(void);
int inject_error_in_all_cr(struct proc *p);
int inject_error_in_gpregs(struct proc *p);

int add_region_to_ws(struct proc *p, u32_t *root, vir_bytes r_base_addr, 
                     int length, phys_bytes us1, phys_bytes us2);
int set_pe_mem_to_ro(struct proc *p, u32_t *root);
void free_pram_mem_block_vaddr(struct proc *current_p, vir_bytes raddr, int len);
void display_hardened_proc(void);
void reset_hardening_attri(struct proc *p);

/**rcounter.c**/
int irh(void);
void intel_arch_insn_counter_init(void);
void intel_arch_insn_counter_reinit(void);
void intel_fixed_insn_counter_init(void);
void intel_fixed_insn_counter_reinit(void);
void update_ins_ctr_switch (void);
void set_remain_ins_counter_value(struct proc *p);
void get_remain_ins_counter_value(struct proc *p);
void read_ins_64(u64_t* t);
void reset_ins_params(struct proc *p);
void get_remain_ins_counter_value_0(struct proc *p);
void set_remain_ins_counter_value_0(struct proc *p);
void set_remain_ins_counter_value_1(struct proc *p);
void enable_counter(void);
void reset_ins_params(struct proc *p);
void reset_counter(void);
/** mca.c**/
int enables_all_mca_features(void);
void enable_loggin_ofall_errors(void);
int mcah(void);
void enable_machine_check_exception(void);
void clears_all_errors(void);

/*hardening_manager.c*/
void init_hardening(void);
void start_dwc(struct proc *p);

/*dwc.c*/
void run_proc_2(struct proc *p);

void enable_hme_event_in_procs(struct proc *p,  
           vir_bytes vaddr, vir_bytes size );
int look_up_page_in_hsr(struct proc *rp,
           vir_bytes vaddr);
int look_up_page_in_hsr(struct proc *rp, 
           vir_bytes vaddr);
void save_context(struct proc *p);
void restore_for_stepping_first_run(struct proc *p);
void abort_pe(struct proc *p);
/*pram.c*/
int check_vaddr_2(struct proc *p, u32_t *root, vir_bytes vaddr, int *rw);
struct pram_mem_block *  look_up_pte(struct proc *current_p,
     int pde, int pte);
struct pram_mem_block *get_pmb(void);
void set_fork_label(struct proc *p);
void set_exec_label(struct proc *p);

/*ssh.c*/
void ssh_init(struct proc *p);
int ssh(struct proc *p);

#endif /* PROTO_H */
