/*** Here the MCA/MCE is implemented
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
#include "mca.h"
#include "htype.h"


static int nbanks;
static int MAX_BANKS_NUMBER;

int enables_all_mca_features(void){
  int status = N_OK;
  u32_t low, high;
  ia32_msr_read(IA32_MCG_CAP, &high, &low);	
  if (low & MCG_CTL_P){
    nbanks = get_n_banks(low);
    MAX_BANKS_NUMBER = nbanks - 1;
    ia32_msr_read(IA32_MCG_CTL, &high, &low);
    printf("IA32_MCG_CTL before low 0x%x, low 0x%x nbanks %d\n", high, low,
          nbanks);
    ia32_msr_write(IA32_MCG_CTL, ALL_1s, ALL_1s);
    ia32_msr_read(IA32_MCG_CTL, &high, &low);
    printf("IA32_MCG_CTL after low 0x%x, low 0x%x\n", high, low);
    return(OK);
  }
  return(status);
}


void enable_loggin_ofall_errors(void){
   int i, t = 0;
   if (cpu_info[CONFIG_MAX_CPUS].family == 0x6 && 
          cpu_info[CONFIG_MAX_CPUS].model < 0x1A)
     t = 1;
   for(i=t; i< nbanks ;i++){
      ia32_msr_write(IA32_MC0_CTL+4*i, ALL_1s, ALL_1s);	
   }	
}

void clears_all_errors(void){
  int i;
  for(i=0;i<nbanks;i++){
    ia32_msr_write(IA32_MC0_STATUS+4*i, 0, 0);
  }
}

void enable_machine_check_exception(void){
  u32_t cr4 = read_cr4() | CR4_MCE;
  write_cr4(cr4);
}

int mcah(void){
  int i;
  u32_t low, high;
  ia32_msr_read(IA32_MCG_STATUS,&high,&low);
  if(low & MCIP){ /* ##### GOT MCA EXCEPTION  ###*/
     printf("##### GOT MCA EXCEPTION  ###");
     if(low & RIPV) /*PE can continue error was corrected*/
       return(OK);   
     /*PE can not continue error was not corrected*/ 
     halt_cpu(); 
  }
  return(EFAULT);
}
