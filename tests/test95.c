/* test 95: execve */

/* created by Emery Assogba */
/* assogba.emery@gmail.com         06-Fevr-2019  12:45:04 */

/* Copyright (C) 2019 by Emery Assogba. All rights reserved. */
/* Used by permission. */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>

#define MAX_ERROR 2
#include "common.h"

int main(void);
void quit(void);

int main()
{
  start(95);
  pid_t pid;
  int status;
  char *const params[] = {"./test96", NULL};
  char *const envs[6] = {"HOME=/home/emery/",
                                "PATH=/bin:/usr/bin/",
                                "TZ=UTC0",
                                "USER=Emery",
                                "LOGNAME=akemery",
                                NULL};
  if ((pid = fork()) ==-1)
        perror("fork error");
  else if (pid == 0) {
        execve("./test96", params, envs);
        quit();
     }
     else {
        pid = wait(&status); 
        if(status!=0) quit();
     }
  quit();
  return(0);			/* impossible */
}
