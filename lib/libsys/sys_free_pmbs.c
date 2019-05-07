#include "syslib.h"
#include <string.h>

int sys_free_pmbs(endpoint_t proc_endpt, 
vir_bytes raddr, int rlength ){
  message m;
  m.FREE_PMBS_ENDPT        = proc_endpt;
  m.FREE_PMBS_REGION_ADDR  = raddr;
  m.FREE_PMBS_REGION_LEN   = rlength;
  return(_kernel_call(SYS_FREEPMBS, &m));
}
