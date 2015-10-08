#include <config.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

/* ---------------------------------------------------------------------------- */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

oid             objid_mib[] = { 1, 3, 6, 1, 2, 1 };
int             numprinted = 0;
int             reps = 10, non_reps = 0;
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

/* ---------------------------------------------------------------------------- */
typedef struct {
  char *peername;
  char *community;
  int   version;
  int   isrun;
} AgentData;

#define STACK_RLIMIT   1024*512 //512KB stack
int    soft_stack_rlimit = STACK_RLIMIT;
struct rlimit lim;

#define NICE_LEVEL     20
#define TOTAL_TIMEOUT  120
#define AGENT_TIMEOUT  3
#define AGENT_RETRIES  1
#define MAXLINELEN     2048

#ifndef PTHREAD_THREADS_MAX
#define PTHREAD_THREADS_MAX 512
#endif

#ifndef __FD_SETSIZE
#define MAX_OPEN_FILES 1024
#else
#define MAX_OPEN_FILES __FD_SETSIZE
#endif

int       Nice_Level   = NICE_LEVEL;
int       TotalTimeout = TOTAL_TIMEOUT;
int       AgentTimeout = AGENT_TIMEOUT;
int       AgentRetries = AGENT_RETRIES;
FILE      *OutFile     = NULL;
char      *OutName     = "";
char      Oid[MAXLINELEN] = "";
int       MultiOutput  = 0;
int       EndSignature = 0;

AgentData AgentTab[PTHREAD_THREADS_MAX];
int       numAgents;

void read_agentsfile(char *fname) 
{
  FILE       *in;
  int        i;
  char       line[MAXLINELEN+1];
  char       *str, *s1, *s2;

  if (!(in = fopen(fname, "r"))) {
    fprintf(stderr, "Can't open agents file [%s]\n", fname);
    exit(1);
  }

  numAgents = 0;
  i = 0;
  do {
    line[0] = 0;
    if (feof(in)) exit(0);
    fgets(line, MAXLINELEN, in);
    if (strlen(line)>0) {
      if (line[strlen(line)-1] == '\n') line[strlen(line)-1] = 0;
      if (strlen(line)>0) {
	str = strdup(line);
	s1 = strtok(str, ":");
	s2 = strtok(NULL, ":");
	AgentTab[numAgents].peername  = s1;
	AgentTab[numAgents].community = s2;
	AgentTab[numAgents].version   = SNMP_VERSION_2c;
	AgentTab[numAgents].isrun = 1;
	numAgents++;
      }
    }
    i++;
  } while (!feof(in));
  fclose(in);
  fprintf(stderr, "Agents to scan [%d]\n", numAgents);
}

/* ---------------------------------------------------------------------------- */

void *agent_bulkwalk(int *data) 
{
  oid             objid_mib[] = { 1, 3, 6, 1, 2, 1 };
  int             numprinted = 0;
  FILE           *output_file = NULL;
  char            output_name_part[MAXLINELEN];
  char            output_name_complete[MAXLINELEN];

  oid             name[MAX_OID_LEN];
  size_t          name_length;
  oid             root[MAX_OID_LEN];
  size_t          rootlen;
  int             status;
  int             exitval = 0;

  netsnmp_session session;
  void            *ss;
  netsnmp_session *sptr;
  netsnmp_pdu     *pdu, *response;
  netsnmp_variable_list *vars;
  int             running, list_running;
  char            *oidlist = NULL, *currmib = NULL;
  char            *oidtokbuf;
  int             currnum;

  if (MultiOutput) {
    snprintf(output_name_part, MAXLINELEN-1, "%s/%s.mwalk.part", OutName, AgentTab[*data].peername);
    snprintf(output_name_complete, MAXLINELEN-1, "%s/%s.mwalk", OutName, AgentTab[*data].peername);
    output_file = fopen(output_name_part, "wb");
    if (!OutFile) {
      fprintf(stderr, "Can't open output file [%s]\n", output_name_part);
      exit(1);
    }
  } else {
    output_file = OutFile;
  }

  snmp_sess_init(&session);
  session.peername      = AgentTab[*data].peername;          //ex "localhost";
  session.community     = (u_char *) AgentTab[*data].community;         //ex "public";
  session.community_len = strlen(AgentTab[*data].community); //
  session.version       = AgentTab[*data].version;           //SNMP_VERSION_2c;
  session.timeout       = AgentTimeout * 1000000L; 
  session.retries       = AgentRetries;

  if (strlen(Oid) > 0) {
    oidlist = strdup(Oid);
    oidtokbuf = (char *) malloc(strlen(Oid)+1);
    currnum = 0;
  } else currnum = -1;

  
  list_running = 1;
  while (list_running)
    {
      // User oid list
      if (strlen(Oid) > 0) {
	if (currnum == 0) currmib = strtok_r(oidlist, ",", &oidtokbuf);
	else              currmib = strtok_r(NULL, ",", &oidtokbuf);
	if (currmib == NULL) { 
	  list_running = 0; 
	  break;
	}
	currnum++;
    
	rootlen = MAX_OID_LEN;
	pthread_mutex_lock(&mut); //snmp_parse_oid is not thread safe
	if (snmp_parse_oid(currmib, root, &rootlen) == NULL) {                                                        
	  snmp_perror(currmib);                                                                                     
	  exit(1);
	}
	pthread_mutex_unlock(&mut);
      } else {
	// Default oid
	memmove(root, objid_mib, sizeof(objid_mib));
	rootlen = sizeof(objid_mib) / sizeof(oid);
	list_running = 0;
      }

      memmove(name, root, rootlen * sizeof(oid));
      name_length = rootlen;

      ss = snmp_sess_open(&session);
      if (!ss) {
	snmp_perror("ack");
	snmp_log(LOG_ERR, "Can't open session!\n");
	exit(2);
      }
      sptr = snmp_sess_session(ss);

      numprinted = 0;
      running = 1;
      while (running) {
	pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
	pdu->non_repeaters   = non_reps;
	pdu->max_repetitions = reps;
	snmp_add_null_var(pdu, name, name_length);
	
	status = snmp_sess_synch_response(ss, pdu, &response);
	if (status == STAT_SUCCESS) {
	  if (response->errstat == SNMP_ERR_NOERROR) {
	    for (vars = response->variables; vars; vars = vars->next_variable) {
	      if ((vars->name_length < rootlen) || (memcmp(root, vars->name, rootlen * sizeof(oid)) != 0)) {
		running = 0;
		continue;
	      }
	      numprinted++;
	      pthread_mutex_lock(&mut);
	      fprintf(output_file, "%s::", AgentTab[*data].peername);
	      fprint_variable(output_file, vars->name, vars->name_length, vars);
	      pthread_mutex_unlock(&mut);
	      if ((vars->type != SNMP_ENDOFMIBVIEW) && (vars->type != SNMP_NOSUCHOBJECT) && (vars->type != SNMP_NOSUCHINSTANCE)) {
		if (vars->next_variable == NULL) {
		  memmove(name, vars->name, vars->name_length * sizeof(oid));
		  name_length = vars->name_length;
		}
	      } else {
		running = 0;
	      }
	    }
	  } else {
	    running = 0;
	  }
	} else if (status == STAT_TIMEOUT) {
	  fprintf(stderr, "Timeout: No Response from %s\n", session.peername);
	  running = 0;
	  exitval = 1;

	  pthread_mutex_lock(&mut);
	  AgentTab[*data].isrun = 0;
	  if (EndSignature) {
	    fprintf(output_file, "%s::=== TIMEOUT ===\n", AgentTab[*data].peername);
	  }
	  pthread_mutex_unlock(&mut);

	} else { /* status == STAT_ERROR */
	  snmp_sess_perror("multiwalk2c", sptr);
	  running = 0;
	  exitval = 1;

	  pthread_mutex_lock(&mut);
	  AgentTab[*data].isrun = 0;
	  if (EndSignature) {
	    fprintf(output_file, "%s::=== STAT_ERROR ===\n", AgentTab[*data].peername);
	  }
	  pthread_mutex_unlock(&mut);

	}
	if (response) snmp_free_pdu(response);
      }
      snmp_sess_close(ss);
    }

  pthread_mutex_lock(&mut);
  AgentTab[*data].isrun = 0;
  if (EndSignature && !exitval) {
    fprintf(output_file, "%s::=== END ===\n", AgentTab[*data].peername);
  }
  pthread_mutex_unlock(&mut);
  fprintf(stderr, "Finish thread [%d]\n", *data);
  if (MultiOutput && !exitval) {
    fclose(output_file);
    rename(output_name_part, output_name_complete);
  }
  pthread_detach(pthread_self());
  return NULL;
}

/* ---------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
  char        infname[MAXLINELEN] = "";
  pthread_t  *pth;

  char       *inf;
  int        *v;
  int        *r;
  int         i, j;
  int         s;

  int         stack;  
  int         arg;
  char        Opts[MAXLINELEN];
  char       *endptr = NULL;

  if (argc < 3) {
    fprintf(stdout, "multiwalk2c ver. %s, wegorz (Z.Kempczynski@marton.pl), GNU GPL License v.2\n\n", VERSION);
    fprintf(stdout, "Usage:   multiwalk2c -f agentsfile [options]\n\n");
    fprintf(stdout, "options: \n");
    fprintf(stdout, "\t-s stack_rlimit  (stack rlimit per thread in kb, default %d kb)\n", STACK_RLIMIT >> 10);
    fprintf(stdout, "\t-T total_timeout (total scanning time in seconds, default %d)\n", TOTAL_TIMEOUT);
    fprintf(stdout, "\t-t timeout       (single agent response timeout, default %d)\n", AGENT_TIMEOUT);
    fprintf(stdout, "\t-r retries       (single agent num. of retries, default %d)\n", AGENT_RETRIES);
    fprintf(stdout, "\t-o output        (output file [single file output context] or\n");
    fprintf(stdout, "\t                  directory [multi file output context])\n");
    fprintf(stdout, "\t-m multi_output  (multi file output? 0 - false [default], 1 - true\n");
    fprintf(stdout, "\t-n nice          (nice level, default %d)\n", NICE_LEVEL);
    fprintf(stdout, "\t-e endsignature  (append signature === END === to output file?\n");
    fprintf(stdout, "\t                  0 - false [default], 1 - true);\n");
    fprintf(stdout, "\t-O output_type   (variable change output type, see snmpbulkwalk -O arg)\n");
    fprintf(stdout, "\t-L miblist       (coma separated mib list to walk, ex. -L system,if\n");
    fprintf(stdout, "\t                  if not set default 1.3.6.1.2 [.iso.org.dod.internet.mib-2] is set)\n");
    fprintf(stdout, "\t-C r<NUM>|n<NUM> (r-repeaters to <NUM>, n-nonrepeaters to n<NUM>)\n");
    fprintf(stdout, "   ex: multiwalk2c -f agents.wlk\n");
    fprintf(stdout, "       multiwalk2c -f agents.wlk -T 120 -t 3\n");
    fprintf(stdout, "       multiwalk2c -f agents.wlk -t 2 -o agents.log\n");
    fprintf(stdout, "       multiwalk2c -f agents.wlk -t 2 -o agents.log -n 10\n");
    fprintf(stdout, "       multiwalk2c -f agents.wlk -t 2 -m 1 -o outdir -e 1\n");
    fprintf(stdout, "       multiwalk2c -f agents.wlk -t 2 -m 1 -o outdir -e 1 -L system,if\n");
    fprintf(stdout, "       multiwalk2c -f agents.wlk -t 2 -m 1 -o outdir -e 1 -On -L system,if\n");
    fprintf(stdout, "       multiwalk2c -f agents.wlk -t 2 -m 1 -o outdir -C r10 -C n1 -L system,if\n");
    exit(0);
  }
  OutFile = stdout;

  
  fprintf(stderr, "Arguments     : %d\n", argc);
  strcpy(Opts, "s:f:T:t:r:o:m:n:e:O:L:C:");
  while ((arg = getopt(argc, argv, Opts)) != EOF) {
    switch (arg) {
    case 's':
      soft_stack_rlimit = atoi(optarg) << 10;
      fprintf(stderr, "Soft stack rlimit : %d kb\n", soft_stack_rlimit >> 10);
      break;

    case 'f':
      strncpy(infname, optarg, MAXLINELEN-1);
      fprintf(stderr, "Agents file   : %s\n", infname);
      break;

    case 'T':
      TotalTimeout = atoi(optarg);
      fprintf(stderr, "Total timeout : %d\n", TotalTimeout);
      break;

    case 't':
      AgentTimeout = atoi(optarg);
      fprintf(stderr, "Agents timeout: %d\n", AgentTimeout);
      break;

    case 'r':
      AgentRetries = atoi(optarg);
      fprintf(stderr, "Agents retries: %d\n", AgentRetries);
      break;

    case 'o':
      OutName = strdup(optarg);
      fprintf(stderr, "Agents output name (file/dir): %s\n", optarg);
      break;

    case 'm':
      fprintf(stderr, "Multi-file context: %s\n", optarg);
      MultiOutput = atoi(optarg);
      break;

    case 'n':
      Nice_Level = atoi(optarg);
      fprintf(stderr, "Nice level    : %d\n", Nice_Level);
      break;

    case 'e':
      fprintf(stderr, "End signature : ");
      if (atoi(optarg)>0) {
	EndSignature = 1;
	fprintf(stderr, "Yes\n");
      } else fprintf(stderr, "No\n");
      break;

    case 'O':
      inf = snmp_out_toggle_options(optarg);                                                        
      if (inf != NULL) {
	fprintf(stderr, "Unknown output option passed to -O: %c.\n", *inf);
	exit (-1); 
      }
      break;

    case 'C':
      endptr = optarg;
      if (*optarg == 'r') {
	reps = strtol(++optarg, &endptr, 0);
	fprintf(stderr, "Reps          : %d\n", reps);
      } else if (*optarg == 'n') {
	non_reps = strtol(++optarg, &endptr, 0);
	fprintf(stderr, "Non           : %d\n", non_reps);
      } else {
	fprintf(stderr, "Unknown flag passed to -C: %c, possible: r<NUM> | n<NUM>\n", *optarg);
	exit(1);
      }
      break;

    case 'L':
      strncpy(Oid, optarg, MAXLINELEN-1);
      fprintf(stderr, "Agents Oid list    : %s\n", Oid);
      break;
    }
  }

  nice(Nice_Level);
  read_agentsfile(infname);

  if (numAgents >= PTHREAD_THREADS_MAX || numAgents >= MAX_OPEN_FILES) {
    fprintf(stderr, "Not enough threads or file descriptors! max = min(%d, %d), required = %d\n", 
	    PTHREAD_THREADS_MAX, MAX_OPEN_FILES, numAgents); 
    exit(-1);
  } else {
    fprintf(stderr, "Max (threads, files) = (%d, %d), task to run = %d\n", 
	    PTHREAD_THREADS_MAX, MAX_OPEN_FILES, numAgents);
  }

  // Set stack soft rlimit 
  stack = getrlimit(RLIMIT_STACK, &lim);
  if (stack)
    fprintf(stderr, "getrlimit error [%s]\n", strerror(stack));
  lim.rlim_cur = soft_stack_rlimit;
  stack = setrlimit(RLIMIT_STACK, &lim);
  if (stack)
    fprintf(stderr, "setrlimit error [%s]\n", strerror(stack));
  printf("Stack rlimits: soft %d kb, hard: %d kb\n", soft_stack_rlimit >> 10, (int) lim.rlim_max >> 10);

  // ---
  init_snmp("snmpapp");
  SOCK_STARTUP;

  // Open OutName if it's single file output context
  if (!MultiOutput) {
    OutFile = fopen(OutName, "wb");
    if (!OutFile) {
      fprintf(stderr, "Can't open output file [%s]\n", OutName);
      exit(1);
    }
  }
 
  pthread_mutex_init(&mut, NULL);
  pth = (pthread_t *) malloc(sizeof(pthread_t) * numAgents);
  v   = (int *) malloc(sizeof(int) * numAgents);
  r   = (int *) malloc(sizeof(int) * numAgents);
  for (i = 0; i < numAgents; i++) {
    v[i] = i;
    s = pthread_create(&pth[i], NULL, (void *) agent_bulkwalk, &v[i]);
    if (s) {
      fprintf(stderr, "Error! Can't create thread [%s]\n", strerror(s));
      exit(-1);
    }
  }

  fprintf(stderr, "Scanning state\n");
  for (j = 0; j < TotalTimeout; j++) {
    int num = 0;
    for (i = 0; i < numAgents; i++) {
      if (!AgentTab[i].isrun) {
	num++;
      }
    }
    if (!(j % 5)) fprintf(stderr, "Unfinished [%d], time left = [%d] \n", numAgents - num, TotalTimeout - j);
    if (numAgents - num == 0) {
      fprintf(stderr, "Unfinished [%d]\n", numAgents - num);
      break;
    }
    sleep(1);
  }
  
  SOCK_CLEANUP;
  exit(0);
}
