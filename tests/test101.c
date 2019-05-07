/* test 101: read, write */
/* Copy  14,660,696 bytes ITER times
 * ressources : 2a.mp4 and 2aa.mp4 */
/* created by Emery Assogba */
/* assogba.emery@gmail.com         22-Avril-2019  15:58:04 */

/* Copyright (C) 2019 by Emery Assogba. All rights reserved. */
/* Used by permission. */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#define BUFFSIZE 4096
#define ITER       50
int main(void){
   int fd1 = open("2a.mp4", 2);
   if(fd1 < 0){
     perror("Can't open file\n");
     exit(-1);
   }
   long fsize_i = lseek(fd1, SEEK_END, 2), fsize;
   lseek(fd1, 0, 0);
   char *buf  = (char*) malloc(sizeof(char)*BUFFSIZE); 
   int i;
   int fd2 = open("2aa.mp4", 2);
   if(fd2 < 0){
     perror("Can't open file\n");
     exit(-1);
   }
   for(i=0 ; i < ITER; i++){
       fsize = fsize_i;
       while(fsize>BUFFSIZE){
          read(fd1, buf, fsize);      
          write(fd2, buf, fsize); 
          fsize-=BUFFSIZE;
       }
       if(fsize > 0){
          read(fd1, buf, fsize);      
          write(fd2, buf, fsize);           
      }
   }
   exit(0);
}
