/* test 100: data size 4K, 8K, 12K, 16K */

/* created by Emery Assogba */
/* assogba.emery@gmail.com         06-Fevr-2019  12:45:04 */

/* Copyright (C) 2019 by Emery Assogba. All rights reserved. */
/* Used by permission. */

#include <stdio.h>
#include <stdlib.h>

#define BUFF_SIZE 4096
#define ITERATIONS   5
#define MAX_ERROR 2
#include "common.h"

int main(void);
void quit(void);
int func_tab(int *tab, int mul);

static int tab_1[BUFF_SIZE*1];
static int tab_2[BUFF_SIZE*2];
static int tab_3[BUFF_SIZE*3];
static int tab_4[BUFF_SIZE*4];
static int tab_5[BUFF_SIZE*5];


int main()
{
  start(100);
  int iter;
  for(iter = 1; iter <= ITERATIONS; iter++) 
    switch(iter){
       case 1:
         if(func_tab(tab_1, iter) < 0) quit();
         break;
       case 2:
         if(func_tab(tab_2, iter) < 0) quit();
         break;
       case 3:
         if(func_tab(tab_3, iter) < 0) quit();
         break;
       case 4:
          if(func_tab(tab_4, iter) < 0) quit();
         break;
       case 5:
          if(func_tab(tab_5, iter) < 0) quit();
         break;
       default:
           break;
    }
  quit();
  return(0);
}

int func_tab(int *tab, int mul){
   int i;
   if(!mul) return(-1);
   for(i=0; i< BUFF_SIZE*mul; i++) *(tab+i) = i;
   for(i=0; i< BUFF_SIZE*mul; i++) if(*(tab+i) != i) return(-1);
   return(0);
}
