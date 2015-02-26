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

/* file is expected to start with a slash */
static void replace_if_changed(char *oldfile)
{
  char newfile[256];
  FILE *new=NULL, *org=NULL;
  int orgsize=0, newsize=0;
  void *orgbuf=NULL, *newbuf=NULL;
  struct stat stbuf;
  int bytes;

  snprintf(newfile, sizeof(newfile), "/tmp%s", oldfile);

  // read new file into memory
  if ((new = fopen(newfile, "r")) == NULL) {
    syslog (LOG_WARNING, "%s(%d): %s: %s", __FILE__, __LINE__, newfile, strerror(errno));
    goto exit;
  }
  if ((fstat(fileno(new), &stbuf) != 0)) {
    syslog (LOG_WARNING, "%s(%d): %s: %s", __FILE__, __LINE__, newfile, strerror(errno));
    goto exit;
  }
  if (!S_ISREG(stbuf.st_mode)) {
    syslog (LOG_WARNING, "%s(%d): %s: not a regular file", __FILE__, __LINE__, newfile);
    goto exit;
  }
  newsize = stbuf.st_size;
  newbuf = malloc(newsize);
  bytes = fread(newbuf, 1, newsize, new);
  if (bytes != newsize) {
    syslog (LOG_WARNING, "%s(%d): %s: %s (%d of %d)", __FILE__, __LINE__, newfile, strerror(errno), bytes, newsize);
    goto exit;
  }

  // read org file into memory
  if ((org = fopen(oldfile, "r+")) == NULL) {
    syslog (LOG_WARNING, "%s(%d): %s: %s", __FILE__, __LINE__, oldfile, strerror(errno));
    goto exit;
  }
  if ((fstat(fileno(org), &stbuf) != 0) || (!S_ISREG(stbuf.st_mode))) {
    syslog (LOG_WARNING, "%s(%d): %s: %s", __FILE__, __LINE__, newfile, strerror(errno));
    goto exit;
  }
  orgsize = stbuf.st_size;
  orgbuf = malloc(orgsize);
  bytes = fread(orgbuf, 1, orgsize, org);
  if (bytes != orgsize) {
    syslog (LOG_WARNING, "%s(%d): %s: %s (%d of %d)", __FILE__, __LINE__, oldfile, strerror(errno), bytes, orgsize);
    goto exit;
  }

  if (!noexec && strcmp(orgbuf, newbuf)) {
    ftruncate(fileno(org), 0);
    fwrite(newbuf, 1, newsize, org);
  }
  
exit:
  if (orgbuf) free(orgbuf);
  if (newbuf) free(newbuf);
  if (new) fclose(new);
  if (org) fclose(org);
  if (!debug) unlink(newfile);
  return;
}

static int p711_prov_init (void)
{
  char *lf;
  char *eth0_address_file = "/sys/class/net/eth0/address";
  FILE *f_address = fopen(eth0_address_file, "r");
  if (!f_address) {
    syslog (LOG_ERR, "%s: %s", eth0_address_file, strerror(errno));
    return 1;
  }
  fgets(p711_eth0_mac, sizeof(p711_eth0_mac), f_address);
  fclose(f_address);
  if ((lf = strchr(p711_eth0_mac, '\n')) != NULL)
    *lf = '\0';
  if (verbose) printf("mac address = %s\n", p711_eth0_mac);
  return curl_global_init(CURL_GLOBAL_DEFAULT);
}

struct string {
  char *ptr;
  size_t len;
};

static void init_string(struct string *s) 
{
  s->len = 0;
  s->ptr = malloc(s->len+1);
  if (s->ptr == NULL) {
    syslog (LOG_ERR, "%s", strerror(errno));
    exit(1);
  }
  s->ptr[0] = '\0';
}

static size_t get_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct string *s = (struct string *) userdata;
  size_t new_len = s->len + size*nmemb;
  s->ptr = realloc(s->ptr, new_len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "realloc() failed\n");
    exit(EXIT_FAILURE);
  }
  memcpy(s->ptr+s->len, ptr, size*nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  //write(1, ptr, size*nmemb);
  return size*nmemb;  
}

static int p711_prov_request(struct string *s)
{
  char *baseurl = "http://ps.p711.net/";
  //char *baseurl = "http://jsonplaceholder.typicode.com/posts/";
  char url[80];
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  snprintf(url, sizeof(url), "%s?mac=%s", baseurl, p711_eth0_mac);
  //snprintf(url, sizeof(url), "%s", baseurl);
  if (verbose) printf("request: %s\n", url);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "P711Box 1.0");
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, get_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)s);
  res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  if (res != 0) {
    syslog (LOG_INFO, "%s: %s", baseurl, curl_easy_strerror(res));
    if (verbose) printf("%s\n", curl_easy_strerror(res));
    return 1;
  }
  return 0;
}

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

int main(int argc, char *argv[])
{
  struct string s;
  json_t *root;
  json_error_t error;
  void *iter;
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

  init_string(&s);
  if (p711_prov_request(&s) != 0) {
    free(s.ptr);
    closelog();
    return 0;
  }
  if (verbose) printf("%s\n", s.ptr);

  //root = json_loadb(s.ptr, s.len, JSON_DECODE_ANY, &error);
  root = json_loads(s.ptr, 0, &error);
  free(s.ptr);
  if (!root) {
    syslog (LOG_WARNING, "%s line %d:%d: %s", error.source, error.line, error.column, error.text);
    printf("%s(%d): error\n", __FILE__, __LINE__);
    closelog();
    return 0;
  }
  //printf("%s(%d): root = %p\n", __FILE__, __LINE__, root);
  if (!json_is_object(root)) {
    syslog (LOG_WARNING, "JSON root is not an object");
    closelog();
    return 0;
  }
  if (mkdir("/tmp/etc", S_IRWXU) == -1 && errno != EEXIST) { 
    syslog (LOG_WARNING, "/tmp/etc: %s", strerror(errno));
    closelog();
    exit(0);
  }
  if (mkdir("/tmp/etc/config", S_IRWXU) == -1 && errno != EEXIST) { 
    syslog (LOG_WARNING, "/tmp/etc: %s", strerror(errno));
    closelog();
    exit(0);
  }
  for (iter = json_object_iter(root); iter; iter = json_object_iter_next(root, iter)) {
    const char *key = json_object_iter_key(iter);
    json_t *value = json_object_iter_value(iter);

    //printf("Key: %s, ", key);
    if (!strcmp(key, "networks") && json_is_array(value)) {
      FILE *zt = fopen("/tmp/etc/config/zerotier", "w");
      if (zt) {
        int i;

        fprintf(zt, "config zerotier sample_config\n");
	fprintf(zt, "\toption enabled %d\n", json_array_size(value) > 0 ? 1 : 0);
	fprintf(zt, "\t#option udp_port '9993'\n");
	fprintf(zt, "\t#option tcp_port '0'\n");
	for (i=0; i < json_array_size(value); i++) {
	  fprintf(zt, "\tlist join '%s'\n", json_string_value(json_array_get(value, i)));
        }
        fclose(zt);
        if (debug) system("cat /tmp/etc/config/zerotier");
      } else {
        syslog (LOG_WARNING, "/tmp/p711_prov/zerotier: %s", strerror(errno));
      }
    }
  }
  replace_if_changed("/etc/config/zerotier");
  if (!debug) {
    rmdir("/tmp/etc/config");
    rmdir("/tmp/etc");
  }
  closelog();
  read_off_memory_status();
  return (0);
}

