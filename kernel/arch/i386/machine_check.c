#include "kernel/kernel.h"
#include "kernel/watchdog.h"
#include "arch_proto.h"
#include "glo.h"
#include <minix/minlib.h>
#include <minix/u64.h>
#include <sys/types.h>
#include <machine/asm.h>
#include "apic.h"
#include "apic_asm.h"

#include "machine_check.h"

// export _cpuid and struct cpu_info
#include "glo.h"


int cpuid_supported(){
   u32_t eax, ebx, ecx, edx;
   //vrai
   int stat=1;
   eax=0;
   _cpuid(&eax, &ebx, &ecx, &edx);
   int maximum_value_input_of_eax = 0;
   maximum_value_input_of_eax=(int)eax;
   if(maximum_value_input_of_eax <= 0)
     stat = 0;
    return stat;
}


u32_t cpuid_features() {
   u32_t eax, ebx, ecx, edx;	
   eax=1;
   _cpuid(&eax, &ebx, &ecx, &edx);
   return edx;
}

int machine_check_supported() {
  int etat = 1;
  if(!(cpuid_features() & MSR) && !(cpuid_features() & MCE)
		&& !(cpuid_features() & MCA)) {
		etat = 0;
  }
  return etat;
}

int enables_all_mca_features(){
  int etat = 1;
  u32_t low, high;
  ia32_msr_read(IA32_MCG_CAP, &high, &low);	
  if (low & MCG_CTL_P) 
    ia32_msr_write(IA32_MCG_CTL, 0XFFFFFFFF, 0XFFFFFFFF);
  else 
    etat = 0;
  return etat;
}


int enable_lmce_capability()
{
  //vrai
  int etat = 1;
  u32_t low_cap,high_cap,low_control,high_control;
  ia32_msr_read(IA32_MCG_CAP, &high_cap, &low_cap);
  //test
  ia32_msr_read(IA32_FEATURE_CONTROL, &high_control, &low_control);
  if((low_cap & MCG_LMCE_P) && (low_control & IA32_FEATURE_CONTROL_LOCK) && 
      (low_control & IA32_FEATURE_CONTROL_LMCE)){
    u32_t low_enable, high_enable;
    ia32_msr_read(MSR_IA32_MCG_EXT_CTL, &high_enable, &low_enable);
    low_enable|=1 << 0;
    ia32_msr_write(MSR_IA32_MCG_EXT_CTL, 0, low_enable);
  } else 
     etat = 0;
  return etat;
}

int max_bank_number(){
   int number= 0;
   u32_t low, high;
   ia32_msr_read(IA32_MCG_CAP, &high, &low);
   int i=0;
   //printf("IA32_MCG_CAP  low %x \n",low);
   for(i=0;i<7;i++){
     if (low & (1<<i)){
	 number++;
     }
   }
   return number;		
}


void enable_loggin_ofall_errors(){
	u32_t eax, ebx, ecx, edx;
	
	eax=1;
	_cpuid(&eax, &ebx, &ecx, &edx);
	int i=0;
	int max_bank_number_read = max_bank_number();
	//printf(" max_bank_number_read %d",max_bank_number_read);
	
	if (cpu_info[CONFIG_MAX_CPUS].family == 6 && cpu_info[CONFIG_MAX_CPUS].model < 0x1A)
	{
	printf("cpu_info Pin \n");
		for(i=1;i<max_bank_number_read;i++){
		//ia32_msr_write(IA32_MCx_CTL(i), 0, 0xFFFFFFFF);
		}
	}
	else
	{
	         //printf("cpu_info ici \n");
		for(i=0;i<max_bank_number_read;i++){
		//printf(" max_bank_number_read %d",IA32_MCx_CTL(i));
		//si le contenu est différents de 
		//ia32_msr_write(IA32_MCx_CTL(i), 0,IA32_MCx_CTL_Val);
		}
	}
	
}

void clears_all_errors(){
	int i=0;
	int max_bank_number_read = max_bank_number();
	for(i=0;i<max_bank_number_read;i++){
		ia32_msr_write(IA32_MCx_STATUS(i), 0, 0);
		}
}

void set_mcexception()
{

}
void enable_machine_check_exception(){
	u32_t cr4 = read_cr4() | CR4_MCE;
	write_cr4(cr4);
}

/*   */


/*  */
void loggin_correctable_machine_check_errors()
{
int finish = 0, i=0;
u32_t high_istatut, low_istatut,high_mcg_statut, low_mcg_statut;

	ia32_msr_read(IA32_MCG_STATUS, &high_mcg_statut, &low_mcg_statut);
	for(i=1;i<max_bank_number();i++){
		ia32_msr_read(IA32_MCx_STATUS(i), &high_istatut, &low_istatut);
		//
		if(low_istatut & MCi_REGISTER_VALID){
			if(high_istatut & MCi_ADDR_REGISTER_VALID)
			{
			//lire le registre
			ia32_msr_read(IA32_MCx_ADDR(i), &high_istatut, &low_istatut);
			}
			if(high_istatut & MCi_MISCV_REGISTER_VALID)
			{
			ia32_msr_read(IA32_MCx_MISC(i), &high_istatut, &low_istatut);
			}
		            //machine check exception is in progress				 //exection is not restable
			if((low_mcg_statut & MCIP) && (high_istatut & MCi_PCC_REGISTER_VALID) && !(low_mcg_statut & RIPV))
			{
			
			}		
		}
	}

}


void log_corrected_error(int MCi){

	u32_t high_istatut, low_istatut,high_miscv, low_miscv,high_addr, low_addr;
	ia32_msr_read(IA32_MCx_STATUS(MCi), &high_istatut, &low_istatut);

	//SAVE IA32_MCi_STATUS;

	if(high_istatut & MCi_MISCV_REGISTER_VALID)
		{
		ia32_msr_read(IA32_MCx_MISC(MCi), &high_miscv, &low_miscv);
		//SAVE IA32_MCi_MISC;

		//set MISCV 0
		ia32_msr_write(IA32_MCx_MISC(MCi),0,0);
		}
	

	if(high_istatut & MCi_ADDR_REGISTER_VALID)
		{
		ia32_msr_read(IA32_MCx_ADDR(MCi), &high_addr, &low_addr);
		//SAVE ADDR

		//set IA32_MCx_ADDR 0
		ia32_msr_write(IA32_MCx_ADDR(MCi),0,0);
		}
	 //set IA32_MCx_STATUS 0
	ia32_msr_write(IA32_MCx_STATUS(MCi),0,0);

}


//max_bank_number_val  max_bank_number() 
// 
void corrected_error_handler(int max_bank_number_val){
	int i=0; 
	u32_t high_istatut, low_istatut,high_cap, low_cap;
	ia32_msr_read(IA32_MCG_CAP, &high_cap, &low_cap);
	for(i=1;i<max_bank_number_val;i++){
		ia32_msr_read(IA32_MCx_STATUS(i), &high_istatut, &low_istatut);
		if(low_istatut & MCi_REGISTER_VALID){
			//It is a corrected error
			if(!(high_istatut & MCi_STATUT_UC)){
				//goto LOGCMCERROR;
				//logcmcerror(i);
			}
			else{
				//Indicates (when set) processor support software erreur recovery
				if(!(low_cap & MCG_SER_P)){
					//goto CONTINUE; Do nothing
					break;
				}
				if(!(low_istatut & MCi_STATUT_AR) && !(low_istatut & MCi_STATUT_S)){
					//THEN (* It is a uncorrected no action required error *)
					//goto LOGCMCERROR;
					//logcmcerror(i);
				}
				//Error Reporting Enable 
				if(!(low_istatut & MCi_STATUT_EN)){
					//THEN (* It is a spurious MCA error *)
					//goto LOGCMCERROR;
					//logcmcerror(i);
				}		
			}
		}	
	}
}
