/* test 96: execve */

/* created by Emery Assogba */
/* assogba.emery@gmail.com         06-Fevr-2019  12:45:04 */

/* Copyright (C) 2019 by Emery Assogba. All rights reserved. */
/* Used by permission. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE  256
#define HOME_P         "HOME"
#define PATH_P         "PATH"
#define TZ_P           "TZ"
#define USER_P         "USER"
#define LOGNAME_P      "LOGNAME"

#define HOME_V         "/home/emery/"
#define PATH_V         "/bin:/usr/bin/"
#define TZ_V           "UTC0"
#define USER_V         "Emery"
#define LOGNAME_V      "akemery"

int main(){
   char * buff = (char*) malloc(BUFFER_SIZE*sizeof(char));

   if(!buff) exit(-1);

   buff = getenv(HOME_P);
   if(strncmp(buff, HOME_V, sizeof(HOME_V) )!=0){
      printf("%s\n", buff);
      exit(-1);
   }

   buff = getenv(PATH_P);
   if(strncmp(buff, PATH_V, sizeof(PATH_V) )!=0){
      printf("%s\n", buff);
      exit(-1);
   }

   buff = getenv(TZ_P);
   if(strncmp(buff, TZ_V, sizeof(TZ_V) )!=0){
      printf("%s\n", buff);
      exit(-1);
   }

   buff = getenv(USER_P);
   if(strncmp(buff, USER_V, sizeof(USER_V) )!=0){
      printf("%s\n", buff);
      exit(-1);
   }

   buff = getenv(LOGNAME_P);
   if(strncmp(buff, LOGNAME_V, sizeof(LOGNAME_V) )!=0){
      printf("%s\n", buff);
      exit(-1);
   }
   return(0);
}
