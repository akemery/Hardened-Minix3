/* test 97: malloc, calloc */

/* created by Emery Assogba */
/* assogba.emery@gmail.com         06-Fevr-2019  12:45:04 */

/* Copyright (C) 2019 by Emery Assogba. All rights reserved. */
/* Used by permission. */

#include <stdlib.h>
#include <string.h>

#define BUFFSIZE    4096
#define ITERATIONS   100

#define MAX_ERROR 2
#include "common.h"

int main(void);
void quit(void);

int main()
{
  start(97);
  char *buff;
  int i,j;
  buff = (char*)malloc(BUFFSIZE*sizeof(char));
  if(!buff) quit();
  memset(buff, 'a', BUFFSIZE);
  for(i = 0; i < BUFFSIZE; i++)
      if(*(buff+i)!='a') quit();

  for(i = 0; i < ITERATIONS; i++){
        buff = (char*)realloc(buff, BUFFSIZE*sizeof(char)*i);
        if(!buff) quit();
        memset(buff, 'a', BUFFSIZE*i);
        for(j = 0; j < BUFFSIZE*i; j++)
           if(*(buff+j)!='a') quit();
  }
  free(buff);
  quit();
  return(0);
}
