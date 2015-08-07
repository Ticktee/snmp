#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "./snmp/snmp.h"



int main(int argc, char *argv[]) 
{
    snmp_init(NULL,0);
    pthread_t thread;
    int flag=0;
   // fprintf(stderr, "Error: OID not increasing: ");
    flag=pthread_create(&thread,NULL,snmp_thread_s,NULL);
    if(flag){
      perror("creread_create error\n");
      return -1;
    }
    pthread_join(thread,NULL);
    //getexample();
    return 0;
}























