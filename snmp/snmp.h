/* @ 20150731*/
#ifndef NET_SNMP_H
#define NET_SNMP_H
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#define MAX_HOST_DEFAULT  200
#define UPDATE_TIME_SECONDS 5
#define HOST_NAME_LEN 16
#define HOST_COMMUNITY_LEN 16



typedef struct snmp_msg
{
  char *host;
  char *community;
  oid  reqoid[MAX_OID_LEN];
  int  oidlen;
  int  opttype;//1-get 2-getwalk
}netsnmp_msg;

typedef struct snmp_data
{
  char *host;
  netsnmp_pdu *response;
}netsnmp_data;


void snmp_get_example();
void * netsnmp_thread_s(void* arg);//synchronize
void * netsnmp_thread_as(void* arg);//asynchronize


#endif