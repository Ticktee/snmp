/* @ 20150731*/
#ifndef NET_SNMP_H
#define NET_SNMP_H
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#define MAX_HOST_DEFAULT  200
#define UPDATE_TIME_SECONDS 5
#define HOST_NAME_LEN 16
#define HOST_COMMUNITY_LEN 16

#define CONFIG_FILE_PATH   "./netsnmpconf.txt"
#define MODULE_NAME        "appname"

typedef struct snmp_msg
{
  char *host;
  char *community;
  oid  reqoid[MAX_OID_LEN];
  int  oidlen;
  int  opttype;//1-get 2-getwalk
}netsnmp_msg;

typedef struct snmp_oid
{
  char *name;
  oid  node_oid[MAX_OID_LEN];
  size_t oidlen;
  struct snmp_oid *next_oid;
}netsnmp_oid;

typedef struct snmp_host
{
  char *name;
  char *community;
  netsnmp_oid hoid;
  int tmout;  //timer expire seconds 
  struct snmp_session *ss;//session
  netsnmp_variable_list *response;
} netsnmp_host;


void snmp_get_example();
void snmp_init(void *args,int type);
void * snmp_thread_s(void* arg);//synchronize
void * snmp_thread_as(void* arg);//asynchronize


#endif