#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <curl/curl.h>
#include <jansson.h>
#include <sys/stat.h>
#include <syslog.h>

/* file is expected to start with a slash */
static int file_changed(char *oldfile)
{
  char newfile[256];
  FILE *new=NULL, *org=NULL;
  int orgsize=0, newsize=0;
  void *orgbuf=NULL, *newbuf=NULL;
  struct stat stbuf;
  int bytes;
  int replaced = 0;

  snprintf(newfile, sizeof(newfile), "/tmp%s", oldfile);

  // read new file into memory
  if ((new = fopen(newfile, "r")) == NULL) {
    WARNING ("%s(%d): %s: %s", __FILE__, __LINE__, newfile, strerror(errno));
    goto exit;
  }
  if ((fstat(fileno(new), &stbuf) != 0)) {
    WARNING ("%s(%d): %s: %s", __FILE__, __LINE__, newfile, strerror(errno));
    goto exit;
  }
  if (!S_ISREG(stbuf.st_mode)) {
    WARNING ("%s(%d): %s: not a regular file", __FILE__, __LINE__, newfile);
    goto exit;
  }
  newsize = stbuf.st_size;
  newbuf = malloc(newsize);
  bytes = fread(newbuf, 1, newsize, new);
  if (bytes != newsize) {
    WARNING ("%s(%d): %s: %s (%d of %d)", __FILE__, __LINE__, newfile, strerror(errno), bytes, newsize);
    goto exit;
  }

  // read org file into memory
  if ((org = fopen(oldfile, "r+")) == NULL) {
    WARNING ("%s(%d): %s: %s", __FILE__, __LINE__, oldfile, strerror(errno));
    goto exit;
  }
  if ((fstat(fileno(org), &stbuf) != 0) || (!S_ISREG(stbuf.st_mode))) {
    WARNING ("%s(%d): %s: %s", __FILE__, __LINE__, newfile, strerror(errno));
    goto exit;
  }
  orgsize = stbuf.st_size;
  orgbuf = malloc(orgsize);
  bytes = fread(orgbuf, 1, orgsize, org);
  if (bytes != orgsize) {
    WARNING ("%s(%d): %s: %s (%d of %d)", __FILE__, __LINE__, oldfile, strerror(errno), bytes, orgsize);
    goto exit;
  }

  if (!noexec && strcmp(orgbuf, newbuf)) {
    ftruncate(fileno(org), 0);
    fwrite(newbuf, 1, newsize, org);
    replaced = 1;
  }
  
exit:
  if (orgbuf) free(orgbuf);
  if (newbuf) free(newbuf);
  if (new) fclose(new);
  if (org) fclose(org);
  if (!debug) {
    unlink(newfile);
  } else {
    fprintf(stderr, "Left this for you: %s\n", newfile);
  }
  return replaced;
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
    ERROR ("%s(%d): %s", __FILE__, __LINE__, strerror(errno));
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
    INFO ("%s(%d): %s: %s", __FILE__, __LINE__, baseurl, curl_easy_strerror(res));
    if (verbose) printf("%s\n", curl_easy_strerror(res));
    return 1;
  }
  return 0;
}

void *do_provision(void *arg)
{
  struct string s;
  json_t *root;
  json_error_t error;
  void *iter;
  const char *firmware_url = NULL;

  init_string(&s);
  if (p711_prov_request(&s) != 0) {
    free(s.ptr);
    closelog();
    return NULL;
  }
  if (verbose) printf("%s\n", s.ptr);

  root = json_loads(s.ptr, 0, &error);
  free(s.ptr);
  if (!root) {
    WARNING ("%s line %d:%d: %s", error.source, error.line, error.column, error.text);
    printf("%s(%d): error\n", __FILE__, __LINE__);
    closelog();
    return NULL;
  }
  if (!json_is_object(root)) {
    WARNING ("%s(%d): JSON root is not an object", __FILE__, __LINE__);
    return NULL;
  }
  if (mkdir("/tmp/etc", S_IRWXU) == -1 && errno != EEXIST) { 
    WARNING ("%s(%d): /tmp/etc: %s", __FILE__, __LINE__, strerror(errno));
    return NULL;
  }
  if (mkdir("/tmp/etc/config", S_IRWXU) == -1 && errno != EEXIST) { 
    WARNING ("%s(%d): /tmp/etc: %s", __FILE__, __LINE__, strerror(errno));
    return NULL;
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
        WARNING ("%s(%d): /tmp/p711_prov/zerotier: %s", __FILE__, __LINE__, strerror(errno));
      }
    }
    if (!strcmp(key, "firmware_url") && json_is_string(value)) {
      firmware_url = json_string_value(value);
    }
    if (!strcmp(key, "force_upgrade") && json_is_true(value)) {
      unlink("/etc/firmware_file");
    }
  }
  if (file_changed("/etc/config/zerotier")) {
    system("/etc/init.d/zerotier restart");
  }
  if (firmware_url) {
    //printf("/usr/bin/p711-fw-upgrade %s", firmware_url);
    execlp("/usr/bin/p711-fw-upgrade", "/usr/bin/p711-fw-upgrade", firmware_url, (char *) NULL);
  }
  json_decref(root);
  if (!debug) {
    rmdir("/tmp/etc/config");
    rmdir("/tmp/etc");
  }
  return NULL;
}

