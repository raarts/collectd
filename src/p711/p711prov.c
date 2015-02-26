#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <curl/curl.h>
#include <jansson.h>
#include <sys/stat.h>
#include <syslog.h>

static char p711_eth0_mac[20];
int verbose = 0;
int debug = 0;
int noexec = 0;

#define ERROR(...)   syslog (LOG_ERR,     __VA_ARGS__)
#define WARNING(...) syslog (LOG_WARNING, __VA_ARGS__)
#define NOTICE(...)  syslog (LOG_NOTICE,  __VA_ARGS__)
#define INFO(...)    syslog (LOG_INFO,    __VA_ARGS__)
#if COLLECT_DEBUG
# define DEBUG(...)  syslog (LOG_DEBUG,   __VA_ARGS__)
#else /* COLLECT_DEBUG */
# define DEBUG(...)  /* noop */
#endif /* ! COLLECT_DEBUG */

#include "do_provision.c"

typedef struct {
    unsigned long size,resident,share,text,lib,data,dt;
} statm_t;

void read_off_memory_status(void)
{
  const char* statm_path = "/proc/self/statm";
  statm_t result;
  int pagesize = sysconf(_SC_PAGESIZE);

  FILE *f = fopen(statm_path,"r");
  if(!f){
    perror(statm_path);
    abort();
  }
  if (7 != fscanf(f,"%ld %ld %ld %ld %ld %ld %ld",
    &result.size,&result.resident,&result.share,&result.text,&result.lib,&result.data,&result.dt)) {
    perror(statm_path);
    abort();
  }
  fclose(f);
  result.size = (result.size * pagesize) / 1024;
  result.resident = (result.resident * pagesize) / 1024;
  result.share = (result.share * pagesize) / 1024;
  result.text = (result.text * pagesize) / 1024;
  result.data = (result.data * pagesize) / 1024;
  if (debug) {
    printf("size=%lukB res=%lukB shared=%lukB text=%lukB data=%lukB\n", 
      result.size, result.resident, result.share, result.text, result.data);
  }
}

static int p711_prov_init (void)
{
  char *lf;
  char *eth0_address_file = "/sys/class/net/eth0/address";
  FILE *f_address = fopen(eth0_address_file, "r");
  if (!f_address) {
    ERROR ("(%s(%d): %s: %s", __FILE__, __LINE__, eth0_address_file, strerror(errno));
    return 1;
  }
  fgets(p711_eth0_mac, sizeof(p711_eth0_mac), f_address);
  fclose(f_address);
  if ((lf = strchr(p711_eth0_mac, '\n')) != NULL)
    *lf = '\0';
  if (verbose) printf("mac address = %s\n", p711_eth0_mac);
  return curl_global_init(CURL_GLOBAL_DEFAULT);
}

int main(int argc, char *argv[])
{
  int c;

  openlog("p711prov", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL0);

  opterr = 0;
  while ((c = getopt (argc, argv, "dnv")) != -1) {
    switch (c) {
      case 'd': debug++; break;
      case 'n': noexec++; break;
      case 'v': verbose++; break;
      default:  printf("Usage: p711prov [-v] [-n]\n"); exit(0);
    }
  } 

  if (p711_prov_init()) {
    closelog();
    return 0;
  }

  do_provision(NULL);
  read_off_memory_status();
  return (0);
}

