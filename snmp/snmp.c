#include "snmp.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include <sys/timerfd.h>
#include <signal.h>


#define MAX_BUF_SIZE  200


static netsnmp_host *Hosts=NULL;
static int  HostsNum=0;
static int  MaxTimeGap=0;
static oid    Objid_mib[] = { 1, 3, 6, 1, 2, 1 };//mib-2 tree


static  void snmp_free_hosts();
static void set_oid_default(netsnmp_oid *node);
static int read_config_file(char *pathname);
static int  send_get_pdu(netsnmp_host* host,netsnmp_oid *node); //for asynchronize thread
static void print_result(netsnmp_variable_list *list);
static int  handle_result(netsnmp_host* host, netsnmp_variable_list** list);
static netsnmp_variable_list *snmp_get(netsnmp_host *host,netsnmp_oid *node);
static netsnmp_variable_list *snmp_walk(netsnmp_host *host,netsnmp_oid *node);
static int asynch_response_cb(int operation, struct snmp_session *sp, int reqid,
                           netsnmp_pdu *pdu, void *magic);

extern int GetProfileString(char *profile, char *AppName, char *KeyName, char *KeyVal);

static void set_oid_default(netsnmp_oid *node)
{
  if(node)
  {
    node->node_oid[0]=1;//theoid[0] = ;
    node->node_oid[1]=3;//theoid[1] = ;
    node->node_oid[2]=6;
    node->node_oid[3]=1;
    node->node_oid[4]=2;
    node->node_oid[5]=1;
    node->name=malloc(strlen("mib-2"));
    strcpy(node->name,"mib-2");
    node->oidlen=6;
    node->next_oid=NULL;
  }
  else
    snmp_perror("set_default_oid err");
}
void snmp_get_example()
{
   struct snmp_session session, *ss;
   struct snmp_pdu *pdu;
   struct snmp_pdu *response;
           
   oid anOID[MAX_OID_LEN];
   size_t anOID_len = MAX_OID_LEN;
   
   struct variable_list *vars;
   int status;

      /*
    * Initialize the SNMP library
    */
   init_snmp("snmpapp");
    snmp_sess_init( &session );                   /* set up defaults */
   session.peername = "192.168.3.1";
   
   /* set up the authentication parameters for talking to the server */
   
   #ifdef DEMO_USE_SNMP_VERSION_3
   
   /* Use SNMPv3 to talk to the experimental server */
   
   /* set the SNMP version number */
   session.version=SNMP_VERSION_3;
        
   /* set the SNMPv3 user name */
   session.securityName = strdup("MD5User");
   session.securityNameLen = strlen(session.securityName);
   
   /* set the security level to authenticated, but not encrypted */
   session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
   
   /* set the authentication method to MD5 */
   session.securityAuthProto = usmHMACMD5AuthProtocol;
   session.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol)/sizeof(oid);
   session.securityAuthKeyLen = USM_AUTH_KU_LEN;
    
   /* set the authentication key to a MD5 hashed version of our
      passphrase "The Net-SNMP Demo Password" (which must be at least 8
      characters long) */
   if (generate_Ku(session.securityAuthProto,
                   session.securityAuthProtoLen,
                   (u_char *) our_v3_passphrase, strlen(our_v3_passphrase),
                   session.securityAuthKey,
                   &session.securityAuthKeyLen) != SNMPERR_SUCCESS)
   {
       snmp_perror(argv[0]);
       snmp_log(LOG_ERR,"Error generating Ku from authentication pass phrase. \n");
       exit(1);
   }
   
   #else /* we'll use the insecure (but simpler) SNMPv1 */
   
   /* set the SNMP version number */
   session.version = SNMP_VERSION_1;
   
   /* set the SNMPv1 community name used for authentication */
   session.community = "test";
   session.community_len = strlen(session.community);
   
   #endif /* SNMPv1 */
      /* windows32 specific initialization (is a noop on unix) */
   SOCK_STARTUP;
   
   /*
    * Open the session
    */
   ss = snmp_open(&session);                     /* establish the session */
     if (!ss) {
       snmp_perror("ack");
       snmp_log(LOG_ERR, "something horrible happened!!!\n");
       exit(2);
   }
      /*
    * Create the PDU for the data for our request.
    *   1) We're going to GET the system.sysDescr.0 node.
    */
   pdu = snmp_pdu_create(SNMP_MSG_GET);
  
     read_objid(".1.3.6.1.2.1.1.1.0", anOID, &anOID_len);
   
   #if OTHER_METHODS
   get_node("sysDescr.0", anOID, &anOID_len);
   read_objid("system.sysDescr.0", anOID, &anOID_len);
   #endif
   snmp_add_null_var(pdu, anOID, anOID_len);
   
      /*
    * Send the Request out.
    */
   status = snmp_synch_response(ss, pdu, &response);
      /*
    * Process the response.
    */
   if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
     /*
      * SUCCESS: Print the result variables
      */
     
   for(vars = response->variables; vars; vars = vars->next_variable)
       print_variable(vars->name, vars->name_length, vars);
         /* manipulate the information ourselves */
     for(vars = response->variables; vars; vars = vars->next_variable) {
       int count=1;
       if (vars->type == ASN_OCTET_STR) {
         char *sp = malloc(1 + vars->val_len);
         memcpy(sp, vars->val.string, vars->val_len);
         sp[vars->val_len] = '\0';
         printf("value #%d is a string: %s\n", count++, sp);
         free(sp);
       }
       else
         printf("value #%d is NOT a string! Ack!\n", count++);
     }
          } else {
     /*
      * FAILURE: print what went wrong!
      */
    
     if (status == STAT_SUCCESS)
       fprintf(stderr, "Error in packet\nReason: %s\n",
               snmp_errstring(response->errstat));
     else
       snmp_sess_perror("snmpget", ss);
    
   }
         /*
    * Clean up:
    *  1) free the response.
    *  2) close the session.
    */
   if (response)
     snmp_free_pdu(response);
   snmp_close(ss);
    
   /* windows32 specific cleanup (is a noop on unix) */
   SOCK_CLEANUP;
} 
  
void print_result(netsnmp_variable_list *list)
{
  if(list != NULL)
    for (; list; list = list->next_variable) 
    {
      print_variable(list->name, list->name_length, list);
    }
}

//GetProfileString(char *profile, char *AppName, char *KeyName, char *KeyVal)
int read_config_file(char *pathname)
{
  int i,flag;
  flag=0;
  char buf[MAX_BUF_SIZE];
  char name[HOST_NAME_LEN];
  char community[HOST_COMMUNITY_LEN];
  char *psrc,*pdes;
  if(pathname==NULL)return -1;

//get hosts_num from configure file 
  if(GetProfileString(pathname,MODULE_NAME,"hosts_num",name))
  {
    snmp_perror("read conf error\n");
    return -1;
  }
  else
  {
    HostsNum=atoi(name);
    if(HostsNum>MAX_HOST_DEFAULT)
    {
      snmp_perror("configure file hosts number expire\n");
      HostsNum=MAX_HOST_DEFAULT;
    }
    Hosts=(netsnmp_host*)malloc(sizeof(netsnmp_host)*HostsNum);
    memset(Hosts,0,sizeof(netsnmp_host)*HostsNum);
  }
//get MaxTimeGap from configure file 
  if(GetProfileString(pathname,MODULE_NAME,"max_time_gap",name))
  {
    snmp_perror("read conf error\n");
    return -1;
  }
  else
  {
    MaxTimeGap=atoi(name);
  }
//get host addrass and community information
  strcpy(name,"host");
  for(i=0; i<HostsNum;i++)
    {
      sprintf(name+4,"%d",i+1);
      if(GetProfileString(pathname,MODULE_NAME,name,buf))
      {
	printf("read host%d addr from conf error\n",i+1);
	HostsNum=i;
	break;
      }
      Hosts[i].name=malloc(HOST_NAME_LEN);
      Hosts[i].community=malloc(HOST_COMMUNITY_LEN);
      sscanf(buf,"%s%s",Hosts[i].name,Hosts[i].community);
    }
   return 0;
}

/*type: 0-synchronize thread
 * 	1-asynchronize thread
 */
void snmp_init(void *args,int type)
{

   netsnmp_host *hs;
   int i=0;
   read_config_file(CONFIG_FILE_PATH);
   for(hs=Hosts;i<HostsNum;i++)
   {
     struct snmp_session sess;
     snmp_sess_init(&sess);                    /* initialize session */
     sess.version = SNMP_VERSION_2c;
     sess.peername = hs[i].name;
     sess.community = hs[i].community;
     sess.community_len = strlen(sess.community);
     if(type)
     {
      sess.callback = asynch_response_cb;      /* default callback */
      sess.callback_magic = &hs[i];
     }
     if (!(hs[i].ss = snmp_open(&sess))) {
       snmp_perror("inti host session");
       continue;
     }
     else
     {
       //printf("timeout:%ld,retries:%d\n",hs[i].ss->timeout,hs[i].ss->retries);
       hs[i].ss->timeout=500000;
       hs[i].ss->retries=3;
     }
     set_oid_default(&(hs[i].hoid));
     hs[i].response=NULL;
   }  
   //for args
   if(type)init_snmp("asynchronize_thread");//init net-snmp library
   else   init_snmp("synchronize_thread");
   
}

/* node:  NULL --get oid in host
 * 	  !NULL--get host' mib data by oid in node */
int send_get_pdu(netsnmp_host* host,netsnmp_oid *node)//for asynchronize thread
{
     netsnmp_pdu *req;
     int flag;
     req = snmp_pdu_create(SNMP_MSG_GET); 
     if(node==NULL)
     {
       if(host==NULL)return 0;
       snmp_add_null_var(req, host->hoid.node_oid,host->hoid.oidlen);
     }else
     {
       snmp_add_null_var(req, node->node_oid,node->oidlen);
     }
     if(host->ss==NULL)return -1;
     if (snmp_send(host->ss, req))//send req
	flag=0;//success
      else {
	flag=1;//fail
	snmp_perror("snmp_send_get_pdu");
	snmp_free_pdu(req);
      }
      return flag;
}
int  handle_result(netsnmp_host *host,netsnmp_variable_list **list)
{
  if(*list)
  {
    print_result(*list);
    snmp_free_varbind(*list);
    *list=NULL;
  }
  else
  {
    snmp_perror("handle_result:no response\n");
    return -1;
  }
  return 0;
}


netsnmp_variable_list *snmp_get(netsnmp_host *host,netsnmp_oid *node)//for synchronize thread
{
     struct snmp_pdu *req;
     int status;
     netsnmp_variable_list *retlist;
     netsnmp_oid *poid;
     //read_objid(".1.3.6.1.2.1.1.1.0", hostoid, &oidlen);
    // snmp_add_null_var(req, hostoid, oidlen);
     if(host->ss==NULL)return NULL;
     if(node==NULL)
     {
       if(host==NULL)return 0;
       poid=&(host->hoid);
     }
     else
     {
       poid=node;
       for(;node;node=node->next_oid)      
       if(node->name&& node->oidlen<=0)
       {
	 node->oidlen=MAX_OID_LEN;//to use snmp_parse_oid() function,need to point out oid size
	 if (snmp_parse_oid(node->name, node->node_oid, &node->oidlen)== NULL) {
	  snmp_perror(node->name);
	  snmp_perror("\n=========snmp_parse_oid error--------\n");
	  exit(1);
	  }
       }     
     }
     req = snmp_pdu_create(SNMP_MSG_GET);
     for(;poid!=NULL;poid=poid->next_oid)//add oid to req
       {
	  snmp_pdu_add_variable(req, poid->node_oid,poid->oidlen, ASN_NULL, NULL, 0);
       }
     
     //status = snmp_synch_response(host->ss, req, &resp);
     status = netsnmp_query_get(req->variables,host->ss);
     if (status == STAT_SUCCESS)//SUCCESS
     {
       retlist=req->variables;
       req->variables=NULL;
       snmp_free_pdu(req);
     }
     else 
     {
       snmp_free_pdu(req);//FAIL
       retlist=NULL;
     }
     return retlist;
}

netsnmp_variable_list *snmp_walk(netsnmp_host *host,netsnmp_oid *node)//for synchronize thread
{
     struct snmp_pdu *req;
     int status;
     netsnmp_variable_list *retlist;
     netsnmp_oid *poid;
     //read_objid(".1.3.6.1.2.1.1.1.0", hostoid, &oidlen);
    // snmp_add_null_var(req, hostoid, oidlen);
     if(host->ss==NULL)return NULL;
     if(node==NULL)
     {
       if(host==NULL)return 0;
       poid=&(host->hoid);
     }
     else
     {
       poid=node;
       for(;node;node=node->next_oid)      
       if(node->name && node->oidlen<=0)
       {
	 node->oidlen=MAX_OID_LEN;//to use snmp_parse_oid() function,need to point out oid size
	 if (snmp_parse_oid(node->name, node->node_oid, &node->oidlen)== NULL) {
	  snmp_perror(node->name);
	  snmp_perror("\n=========snmp_parse_oid error--------\n");
	  exit(1);
	  }
       }     
     }
     req = snmp_pdu_create(SNMP_MSG_GET);
     for(;poid!=NULL;poid=poid->next_oid)//add oid to req
       {
	  snmp_pdu_add_variable(req, poid->node_oid,poid->oidlen, ASN_NULL, NULL, 0);
       }
     
     //status = snmp_synch_response(host->ss, req, &resp);
     status = netsnmp_query_walk(req->variables,host->ss);
     if (status == STAT_SUCCESS)//SUCCESS
     {
       retlist=req->variables;
       req->variables=NULL;
       snmp_free_pdu(req);
     }
     else 
     {
       snmp_free_pdu(req);//FAIL
       retlist=NULL;
     }
     return retlist;
}
 
int asynch_response_cb(int operation, struct snmp_session *sp, int reqid,
                           netsnmp_pdu *pdu, void *magic)
{
  return 0;
}
void snmp_free_hosts(void *reval)
{
  int i=0;
  if(HostsNum>0)
  for(i=HostsNum-1;i>=0;i--)
  {
    if(Hosts[i].name)free(Hosts[i].name);
    if(Hosts[i].community)free(Hosts[i].community);
    if(Hosts[i].ss)snmp_close(Hosts[i].ss);
  }
  if(Hosts)free(Hosts);
  Hosts=NULL;
}
 
void * snmp_thread_s(void* arg)
{
  int i=0;
  netsnmp_pdu * resp;
  int status=0;
  netsnmp_variable_list *result;
  netsnmp_oid node={"sysDescr",0,0
		  // , { 1, 3, 6, 1, 2, 1 ,1,1,0}
		  // ,9
		    };	   
   //create timer
  int tfd;
  struct itimerspec ts, ots; /*struct timespec {
						time_t tv_sec;                //Seconds 
						long   tv_nsec;               //Nanoseconds 
					 };*/
  //memset(&se,0,sizeof(se));
  /*
  se.sigev_notify =SIGEV_SIGNAL ;   //SIGEV_NONE:ignored remainder     
				     //SIGEV_SIGNAL:   USE signal to blind signal with function
				     // SIGEV_THREAD:se.sigev_signo is ignored
  se.sigev_notify_function =snmp_process_s;
  se.sigev_signo=SIGRTMIN+1;
  se.sigev_value.sival_int = 10;
  if(timer_create(CLOCK_MONOTONIC, &se, &tid) < 0){
      perror("timer_creat");
      return NULL;
  }*/
  tfd=timerfd_create(CLOCK_MONOTONIC,0);//0/o_NONBLOCK
  if(tfd==-1)snmp_perror("timerfd_create error\n");
  ts.it_value.tv_sec = 3;
  ts.it_value.tv_nsec = 0;
  ts.it_interval.tv_sec = MaxTimeGap;
  ts.it_interval.tv_nsec = 0; //纳妙级
  if(timerfd_settime(tfd,TFD_TIMER_ABSTIME, &ts, &ots)   <   0){  //TIMER_ABSTIME
    perror("timerfd_settime");
    return NULL;
  }
   //main loop,wait for time out
   uint64_t tfd_exp=0;
   int run=1;
   ssize_t size;
   for(;run;)
   {
     if(size=read(tfd,&tfd_exp,sizeof(uint64_t))>0)
     {
	for(i=0;i<HostsNum;i++)
	{
	  result= snmp_walk(&Hosts[i],&node);
	  //result= snmp_get(&Hosts[i],&node);
	  if(result)
	  {
	    handle_result(&Hosts[i],&result);
	    if(result)snmp_free_varbind(result);
	  }
	  else  
	   snmp_perror("snmp_walk/get error\n");
	 }
	// printf("size:%ld  tfd_exp:%ld,result:%d\n",size,tfd_exp,result); 
     }
     else
     {
        printf("read error,size:%ld  tfd_exp:%ld\n",size,tfd_exp);
     }
   }
  printf("snmp_process_s end!!!!!!!!!!!\n\n");
}
  
  
void * snmp_thread_as(void* arg) //asynchronize
{
   int count,run;
   snmp_init(arg,1);
   
   
}






















