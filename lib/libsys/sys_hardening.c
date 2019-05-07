/*sys_hardening.c path: 
 * src/minix/lib/libsys/sys_hardening.c*/
#include "syslib.h"
#include <string.h>
int sys_hardening(proc_endpt, htask_type, 
	htask_pendt, htask_pname, namelen)
endpoint_t proc_endpt;	/* process endpoint */
int  htask_type;	/* type of task */
endpoint_t htask_pendt;	/* process to hard */
char *htask_pname;	/* process to hard */
int namelen;
{
  message m;
  m.HTASK_ENDPT        = proc_endpt;
  m.HTASK_P_ENDPT      = htask_pendt;
  if(htask_pname!=NULL)
     m.HTASK_PNAME = (vir_bytes)htask_pname;
  else
     m.HTASK_PNAME = 0L;
  m.HTASK_TYPE         =  htask_type;  
  return(_kernel_call(SYS_HARDENING, &m));
}
