#include "syslib.h"

int sys_hmem_map(proc_endpt, first_phys, 
	second_phys, pram2_phys, r_id)
endpoint_t proc_endpt;		/* process endpoint */
phys_bytes first_phys;		/* first run frame phys addr */
phys_bytes second_phys;		/* second run frame phys addr */
phys_bytes pram2_phys;		/* back frame phys addr */
int r_id;
{
/* Send to the kernel from the VM the phys addr of allocated frame
 */

  message m;

  m.HMEM_MAP_ENDPT        = proc_endpt;
  m.HMEM_MAP_FIRST_ADDR   = (long) first_phys;
  m.HMEM_MAP_SECOND_ADDR  = (long) second_phys;
  m.HMEM_MAP_PRAM2_ADDR   = (long) pram2_phys;
  m.HMEM_R_ID             = r_id;

  return(_kernel_call(SYS_HMEM_MAP, &m));
}
