#include <lib.h>
#include <unistd.h>

int disable_hardening(void){
  message m;
  return(_syscall(PM_PROC_NR,PM_DISABLE_HARDENING,&m));
}
