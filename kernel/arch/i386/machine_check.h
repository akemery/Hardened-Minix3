/***   Author: Emery Kouassi Assogba
 ***   Email: assogba.emery@gmail.com
 ***   Phone: 0022995222073
 ***   12/03/2019 lln***/

#ifndef MACHINE_CHECK_H
#define MACHINE_CHECK_H

#include <minix/const.h>
#include <sys/cdefs.h>
#include "machine_check_const.h"


/*Log Structs */

struct log {
  int flag;
  int reporting_error_bank_count;
  u32_t cpu_family;
  u32_t cpu_model;
  char type_of_error[4];
  u32_t status[7];
  u32_t addr[7];
  u32_t misc[7];
};

/*machine_check_initialisation */
int cpuid_supported(void);
u32_t cpuid_features(void);
int machine_check_supported(void);
int enables_all_mca_features(void);
int enable_lmce_capability(void);
int max_bank_number(void);
void enable_loggin_ofall_errors(void);

//BIOS detects Power-on reset)
//BIOS clears all errors only on power-on reset
void clears_all_errors(void);

//enable machine check exception
void enable_machine_check_exception(void);

//
void set_mcexception(void);

/* Corrected Error (EC)*/
void corrected_error_handler(int);
void log_corrected_error(int);

/*######### */
void loggin_correctable_machine_check_errors(void);


#endif /* MACHINE_CHECK_CONST_H */
