#include "syslib.h"
#include <string.h>
/*path: src/minix/lib/libsys/sys_addregionto_ws.c*/
int sys_addregionto_ws(proc_endpt, raddr, 
	rlength, us1, us2)
endpoint_t proc_endpt;	/* process endpoint */
vir_bytes  raddr;	/* region addr */
int  rlength;		/* region length */
phys_bytes us1;
phys_bytes us2;
{
  message m;
  m.HADDREGIONTOWS_ENDPT     = proc_endpt;
  m.HADDREGIONTOWS_RADDR     = raddr;
  m.HADDREGIONTOWS_RLENGTH   = rlength;
  m.HADDREGIONTOWS_US1       = us1;
  m.HADDREGIONTOWS_US2       = us2;
  return(_kernel_call(SYS_ADDREGIONTOWS, &m));
}
