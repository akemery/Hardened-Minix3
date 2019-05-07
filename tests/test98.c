/* test 98: malloc, free */

/* created by Emery Assogba */
/* assogba.emery@gmail.com         06-Fevr-2019  12:45:04 */

/* Copyright (C) 2019 by Emery Assogba. All rights reserved. */
/* Used by permission. */

#include <stdlib.h>
#include <string.h>

#define BUFFSIZE    4096
#define ITERATIONS    10

#define MAX_ERROR 2
#include "common.h"

int main(void);
void quit(void);

int main()
{
  start(98);
  char *buff;
  void *ptr;
  int i,j;
  
  for(i = 1; i <= ITERATIONS; i++){
      buff = (char*)malloc(BUFFSIZE*sizeof(char)*i);
      if(!buff) quit();
      ptr = memset(buff, 'a', BUFFSIZE);
      for(i = 0; i < BUFFSIZE; i++)
         if(*(buff+i)!='a') quit();
      free(buff);
 
  }
  quit();
  return(0);
}
