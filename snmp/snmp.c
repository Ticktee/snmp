#include "snmp.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>


#define MAX_BUF_SIZE  200



typedef struct snmp_node
{
  char *name;
  oid  node_oid[MAX_OID_LEN];
  size_t oidlen;
}netsnmp_node;

typedef struct snmp_host
{
  char *name;
  char *community;
  netsnmp_node hoid;
  struct snmp_session *ss;
} netsnmp_host;


static netsnmp_host *Hosts;
static int  HostsNum=0;
static int  MaxTimeGap=0;
static char * Path="./netsnmpconf.txt";
static char * SoftName="appname";
static oid    Objid_mib[] = { 1, 3, 6, 1, 2, 1 };//mib-2 tree


static void set_default_oid(oid *theoid);
static void init_hosts(void *args,int type);
static void free_hosts(netsnmp_host *host);
static int read_config_file(char *pathname);
static int  send_get_pdu(netsnmp_host* host,netsnmp_node *node); //for asynchronize thread
static void print_response(netsnmp_pdu *response);
static int  handle_response(netsnmp_host* host, netsnmp_pdu** response);
static netsnmp_pdu *snmp_get(netsnmp_host *host,netsnmp_node *node);
static int    snmp_walk(netsnmp_host *host,netsnmp_node *node);
static int asynch_response_cb(int operation, struct snmp_session *sp, int reqid,
                           netsnmp_pdu *pdu, void *magic);

extern int GetProfileString(char *profile, char *AppName, char *KeyName, char *KeyVal);


static void set_oid_default(netsnmp_node *node)
{
  oid *theoid=node->node_oid;
  if(node)
  {
    *theoid++=1;
    *theoid++=3;
    *theoid++=6;
    *theoid++=1;
    *theoid++=2;
    *theoid=1;
    node->name=malloc(strlen("mib-2"));
    strcpy(node->name,"mib-2");
    node->oidlen=6;
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
  
void print_response(netsnmp_pdu *response)
{
  netsnmp_variable_list *vars;
  if(response != NULL)
    for (vars = response->variables; vars; vars = vars->next_variable) 
    {
      print_variable(vars->name, vars->name_length, vars);
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
  if(GetProfileString(pathname,SoftName,"hosts_num",name))
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
  if(GetProfileString(pathname,SoftName,"max_time_gap",name))
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
      if(GetProfileString(pathname,SoftName,name,buf))
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
void init_hosts(void *args,int type)
{

   netsnmp_host *hs;
   int i=0;
   read_config_file(Path);
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
      sess.callback = asynch_response_cb;            /* default callback */
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
   }  
   //for args
}

/* node:  NULL --get oid in host
 * 	  !NULL--get host' mib data by oid in node */
int send_get_pdu(netsnmp_host* host,netsnmp_node *node)//for asynchronize thread
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
int  handle_response(netsnmp_host *host,netsnmp_pdu **response)
{
  if(*response)
  {
    print_response(*response);
    snmp_free_pdu(*response);
    *response=NULL;
  }
  else
  {
    snmp_perror("handle_response:no response\n");
    return -1;
  }
  return 0;
}


netsnmp_pdu *snmp_get(netsnmp_host *host,netsnmp_node *node)//for synchronize thread
{
     struct snmp_pdu *req, *resp;
     int status;
     req = snmp_pdu_create(SNMP_MSG_GET);
     //read_objid(".1.3.6.1.2.1.1.1.0", hostoid, &oidlen);
    // snmp_add_null_var(req, hostoid, oidlen);
     
     if(node==NULL)
     {
       if(host==NULL)return 0;
       snmp_add_null_var(req, host->hoid.node_oid,host->hoid.oidlen);
     }else
     {
       if(node->oidlen>0)
	  snmp_add_null_var(req, node->node_oid,node->oidlen);
       else if(node->name)
       {
	 node->oidlen=MAX_OID_LEN;//to use snmp_parse_oid() function,need to point out oid size
	 if (snmp_parse_oid(node->name, node->node_oid, &node->oidlen)== NULL) {
	  snmp_perror(node->name);
	  exit(1);
	  }
	 snmp_add_null_var(req, node->node_oid,node->oidlen);
       }
       else 
       {
	 snmp_perror("snmp_get node have no data\n");
       }
     }
     if(host->ss==NULL)return NULL;
     status = snmp_synch_response(host->ss, req, &resp);
     if (status == STAT_SUCCESS && resp->errstat == SNMP_ERR_NOERROR)return resp;//SUCCESS
     else 
     {
       snmp_free_pdu(resp);//FAIL
       return NULL;
     }
}

/*return val:0-exit success
 * 	     1-exit oid or session error
 * 	     2-packet error
 */
int    snmp_walk(netsnmp_host *host,netsnmp_node *node)
{
    netsnmp_pdu    *pdu, *response;
    netsnmp_variable_list *vars;
  //  oid             objid_mib[] = { 1, 3, 6, 1, 2, 1 };
    //int             numprinted = 0;

	netsnmp_node    name;
	oid             end_oid[MAX_OID_LEN];
	size_t          end_len = 0;
	int             count;
	int             running;
	int             status = STAT_ERROR;
	int 		check=!0;
	int             exitval = 0;
	/*
	* get the initial object and subtree
	*/
	if(node->oidlen>0){//use node oid first
	  end_len=node->oidlen;
	  memmove(end_oid,node->node_oid, sizeof(node->node_oid));
	}
	else if (node->name){
	        end_len = MAX_OID_LEN;
		if (snmp_parse_oid(node->name, end_oid, &end_len) == NULL) {
			snmp_perror(host->name);
			exit(1);
		}
	}	  
	else if (host->hoid.oidlen>0) {//node is empty,then use host oid info
		/*
		* specified oid in the struct snmp_host
		*/
		end_len = host->hoid.oidlen;
		for( count=0;count<end_len;count++)end_oid[count]=host->hoid.node_oid[count];
	}
	else if(host->hoid.name){
	        end_len = MAX_OID_LEN;
		if (snmp_parse_oid(host->hoid.name, end_oid, &end_len) == NULL) {
			snmp_perror(host->hoid.name);
			exit(1);
		}
	}
	else {
		/*
		* use default value
		*/
		memmove(end_oid, Objid_mib, sizeof(Objid_mib));
		end_len = sizeof(Objid_mib) / sizeof(oid);
	}

	SOCK_STARTUP;//linux :null,win32 :winsock_startup()

	/*
	* open an SNMP session
	*/
	if (host->ss == NULL) {
		/*
		* diagnose snmp_open errors with the input netsnmp_session pointer
		*/
		snmp_sess_perror("snmpwalk:host seesion not init", NULL);
		SOCK_CLEANUP;
		exit(1);
	}
	/*
	* get first object to start walk
	*/
	memmove(name.node_oid, end_oid, end_len * sizeof(oid));
	name.oidlen = end_len;
	response=snmp_get(host,&name);
	handle_response(host,&response);
	running = 1;
	
	while (running) {
		/*
		* create PDU for GETNEXT request and add object name to request
		*/
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(pdu, name.node_oid, name.oidlen);
		/*
		* do the request
		*/
		status = snmp_synch_response(host->ss, pdu, &response); 
		if (status == STAT_SUCCESS) {
			if (response->errstat == SNMP_ERR_NOERROR) {
				/*
				* check resulting variables
				*/
				//
				for (vars = response->variables; vars;
					vars = vars->next_variable) {
				       //if(response)printf("testi===============\n");
					if (snmp_oid_compare(end_oid, end_len,
						vars->name, end_len) < 0) {
						/*
						* not part of this subtree
						*/						
						running = 0;
						continue;
					}
					//if(response)printf("testi===============\n");
					//print_variable(vars->name, vars->name_length, vars);
					if ((vars->type != SNMP_ENDOFMIBVIEW) &&
						(vars->type != SNMP_NOSUCHOBJECT) &&
						(vars->type != SNMP_NOSUCHINSTANCE)) {
						/*
						* not an exception value
						*/
						if (check
							&& snmp_oid_compare(name.node_oid, name.oidlen,
							vars->name,
							vars->name_length) >= 0) {
							fprintf(stderr, "Error: OID not increasing: ");
							fprint_objid(stderr, name.node_oid, name.oidlen);
							fprintf(stderr, " >= ");
							fprint_objid(stderr, vars->name,
								vars->name_length);
							fprintf(stderr, "\n");
							running = 0;
							exitval = 1;
						}
						//if(response)printf("testing+0===============\n");
						memmove((char *)name.node_oid, (char *)vars->name,
							vars->name_length * sizeof(oid));
						name.oidlen = vars->name_length;
					}
					else
						/*
						* an exception value, so stop
						*/
						running = 0;
				}
				//printf("testing+1==for parse=============\n");
				if(running)handle_response(host,&response);
			}
			else {
				/*
				* error in response, print it
				*/
				running = 0;
				if (response->errstat == SNMP_ERR_NOSUCHNAME) {
					printf("End of MIB\n");
				}
				else {
					fprintf(stderr, "Error in packet.\nReason: %s\n",
						snmp_errstring(response->errstat));
					if (response->errindex != 0) {
						fprintf(stderr, "Failed object: ");
						for (count = 1, vars = response->variables;
							vars && count != response->errindex;
							vars = vars->next_variable, count++)
							/*EMPTY*/;
						if (vars)
							fprint_objid(stderr, vars->name,
							vars->name_length);
						fprintf(stderr, "\n");
					}
					exitval = 2;
				}
			}
		}
		else if (status == STAT_TIMEOUT) {
			fprintf(stderr, "Timeout: No Response from %s\n",
				host->ss->peername);
			running = 0;
			exitval = 1;
		}
		else {                /* status == STAT_ERROR */
			snmp_sess_perror("snmpwalk", host->ss);
			running = 0;
			exitval = 1;
		}
		if (response)
			snmp_free_pdu(response);
	}
	/*if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
		NETSNMP_DS_WALK_PRINT_STATISTICS)) {
		printf("Variables found: %s\n", );
	}*/
	return  exitval;
}

 
int asynch_response_cb(int operation, struct snmp_session *sp, int reqid,
                           netsnmp_pdu *pdu, void *magic)
{
  return 0;
}
void free_hosts(netsnmp_host *host)
{
  int i=0;
  for(i=MAX_HOST_DEFAULT-1;i>=0;i--)
  {
    if(Hosts[i].name)free(Hosts[i].name);
    if(Hosts[i].community)free(Hosts[i].community);
    if(Hosts[i].ss)snmp_close(Hosts[i].ss);
  }
  free(Hosts);
  Hosts=NULL;
}

void snmp_process_s(union sigval v)
{
  int i=0;
  netsnmp_pdu * resp;
  int status=0;
  netsnmp_node node={"ip",0,0
		   // , { 1, 3, 6, 1, 2, 1 ,1,1,0}
		   // ,9
		    };	      
  for(;i<HostsNum;i++)
  {
   if(v.sival_int==10)printf("\n-----%s:%d:Hostnum:%d------\n",Hosts[i].name,i,HostsNum);
   status= snmp_walk(&Hosts[i],&node);
 /**  if(resp)handle_response(&resp);
   else
     snmp_perror("snmp_process_s\n"); */
   printf("snmpwalk return \n");
   if(status)snmp_perror("snmp_process_s error\n");
  }
  printf("snmp_process_s end!!!!!!!!!!!\n\n");
}
    
void * netsnmp_thread_s(void* arg)
{
   int count,run;
   init_snmp("synchronizeapp");
   init_hosts(arg,0);
   
   //create timer
  timer_t tid;
  struct sigevent se;
  struct itimerspec ts, ots; /*struct timespec {
						time_t tv_sec;                //Seconds 
						long   tv_nsec;               //Nanoseconds 
					 };*/
  memset(&se,0,sizeof(se));
  se.sigev_notify = SIGEV_THREAD;   
  se.sigev_notify_function =snmp_process_s;
  se.sigev_value.sival_int = 10;
  if(timer_create(CLOCK_MONOTONIC, &se, &tid) < 0){
      perror("timer_creat");
      return NULL;
  }
  ts.it_value.tv_sec = 2;
  ts.it_value.tv_nsec = 0;
  ts.it_interval.tv_sec = MaxTimeGap;
  ts.it_interval.tv_nsec = 0; //纳妙级
  if(timer_settime(tid, 0, &ts, &ots)   <   0){  //TIMER_ABSTIME
    perror("timer_settime");
    return NULL;
  }
   //main loop,wait for time out
  for(;;)pause();
}
  
  
void * netsnmp_thread_as(void* arg) //asynchronize
{
   int count,run;
   init_snmp("synchronizeapp");
   init_hosts(arg,1);
}






















