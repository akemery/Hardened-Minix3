/* test 99: stack size 4K, 8K, 12K, 16K */

/* created by Emery Assogba */
/* assogba.emery@gmail.com         06-Fevr-2019  12:45:04 */

/* Copyright (C) 2019 by Emery Assogba. All rights reserved. */
/* Used by permission. */

#include <stdio.h>
#include <stdlib.h>

#define BUFF_SIZE 4096
#define ITERATIONS   4
#define MAX_ERROR 2
#include "common.h"

int main(void);
void quit(void);
int func_tab( int mul);


int main()
{
  start(99);
  int iter;
  for(iter = 0; iter < ITERATIONS; iter++) 
   if(func_tab(iter) < 0) quit();
  quit();
  return(0);
}

int func_tab( int mul){
   int i;
   if(mul < 0 || !mul) return(-1);
   int tab[BUFF_SIZE*mul];
   for(i=0; i< BUFF_SIZE*mul; i++) tab[i] = i;
   for(i=0; i< BUFF_SIZE*mul; i++) if(tab[i] != i) return(-1);
   return(0);
}
