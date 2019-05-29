/* path: src/minix/tests/
*  hardening:  src/minix/tests/hardening.c
*  This program can be call to enable or disable
*  hardening
*  A system cal is made from the user process to the PM
*  servers.
*  The PM server makes a kernel call to the micro-kernel
*  The micro-kernel enable the hardening at micro-kernel
*  level
*  The micro-kernel sends message to the VM
*  The VM enable the hardening at VM level
*  USAGE: 
*       - hardening <1> to enable hardening for all 
*          new process (fork)
*       - hardening <2> to disable hardening for all 
*          new process (fork)
*       - hardening <4> <pid> to enable hardening for 
*         process reprented by pid
*       - hardening <8> <pid> to disable hardening for 
*          process reprented by pid
*/
/* created by Emery Assogba */
/* assogba.emery@gmail.com         
 * 06-Fevr-2019  12:45:04 */

/* Copyright (C) 2019 by Emery Assogba. 
 * All rights reserved. */
/* Used by permission. */
#include <unistd.h>
#include <stdlib.h>
#include "hardening.h"
#include <string.h> 
#include <stdio.h>
static void usage(char *prog_name);
int main(int argc, char *argv[]){
   int r = OK;
   if(argc<2){
     usage(argv[0]);
     return(r);
   }
   int type = atoi(argv[1]);
   int pid;
   switch(type){
       case HTASK_EN_HARDENING_ALL_F:
          if((r = hardening(HTASK_EN_HARDENING_ALL_F,
                  PID_NONE, NULL, 0))!=OK)
             printf("Enable hardening for all new"
                       " procs failed %d\n", r);
          break;     
     case HTASK_DIS_HARDENING_ALL_F:
          if((r = hardening(HTASK_DIS_HARDENING_ALL_F, 
                     PID_NONE, NULL, 0))!=OK)
             printf("Disable hardening for all new "
                          "procs failed %d\n", r);
          break;
     case HTASK_EN_HARDENING_PID:
          if(argc!=3){
            usage(argv[0]);
          return(r);
          }
          pid = atoi(argv[2]);
          if((r=hardening(HTASK_EN_HARDENING_PID, 
                    pid, NULL, 0))!=OK)
             printf("Enable hardening for %d"
                        " procs failed %d\n", pid, r);           
          break;
     case HTASK_DIS_HARDENING_PID:
          pid = atoi(argv[2]);
          if(argc!=3){
            usage(argv[0]);
          return(r);
          }
          if((r=hardening(HTASK_DIS_HARDENING_PID, 
                     pid, NULL, 0))!=OK)
             printf("Disable hardening for %d"
                     " procs failed %d\n", pid, r);
          break;
     case HTASK_DISPLAY_HARDENIG:
          if((r = hardening(HTASK_DISPLAY_HARDENIG,
                  PID_NONE, NULL, 0))!=OK)
             printf("Displaying hardened"
                       " procs failed %d\n", r);
          break;
     default:
          usage(argv[0]);
          break;           
   }
   return(r);
}
static void usage(char *prog_name){
   printf("USAGE %s <reqtype> [pid] [name]\n", 
                   prog_name);
   printf("%s <1> : to enable hardening for all"
                   " new process \n", prog_name);
   printf("%s <2> : to disable hardening for all"
                  " new process \n", prog_name);
   printf("%s <4> <pid> to enable hardening"
       " for process reprented by pid \n", prog_name);
   printf("%s <8> <pid> to disable hardening "
       " for process reprented by pid \n", prog_name);
}
