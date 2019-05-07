#include <lib.h>
#include <unistd.h>

int enable_hardening(void){
  message m;
  return(_syscall(PM_PROC_NR,PM_ENABLE_HARDENING,&m));
}
