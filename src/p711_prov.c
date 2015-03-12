/**
 * collectd - src/p711_prov.c
 * Copyright (C) 2005-2008  Florian octo Forster
 * Copyright (C) 2009       Manuel Sanmartin
 * Copyright (C) 2013       Vedran Bartonicek
 * Copyright (C) 2015       Ron Arts
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Florian octo Forster <octo at collectd.org>
 *   Manuel Sanmartin
 *   Vedran Bartonicek <vbartoni at gmail.com>
 *   Ron Arts <ron.arts at gmail.com>
 **/

#define _DEFAULT_SOURCE
#define _BSD_SOURCE

#include "collectd.h"
#include "common.h"
#include "plugin.h"

#include <unistd.h>
#include <time.h>
#include <curl/curl.h>
#include <jansson.h>
#include <sys/stat.h>

static _Bool prov_frequency_p711_prov = 0;
static char p711_prov_eth0_mac[20];

#define PLUGIN_NAME "p711_prov"
#define PLUGIN_VERSION "1.0"

static const char *config_keys[] =
{
  "ProvFrequency"
};
static int config_keys_num = STATIC_ARRAY_SIZE (config_keys);

static int p711_prov_config (const char *key, const char *value)
{
  printf("key: %s value: %s\n", key, value);
  if (strcasecmp (key, "ProvFrequency") == 0)
    prov_frequency_p711_prov = atoi(value);
  return (-1);
}

/*
static void p711_prov_submit (gauge_t snum, gauge_t mnum, gauge_t lnum)
{
  value_t values[3];
  value_list_t vl = VALUE_LIST_INIT;

  values[0].gauge = snum;
  values[1].gauge = mnum;
  values[2].gauge = lnum;

  vl.values = values;
  vl.values_len = STATIC_ARRAY_SIZE (values);

  sstrncpy (vl.host, hostname_g, sizeof (vl.host));
  sstrncpy (vl.plugin, "p711_prov", sizeof (vl.plugin));
  sstrncpy (vl.type, "p711_prov", sizeof (vl.type));

  plugin_dispatch_values (&vl);
}
*/

static int p711_prov_init (void)
{
  char *lf;
  char *eth0_address_file = "/etc/eth0-physmac";
  FILE *f_address = fopen(eth0_address_file, "r");
  if (!f_address) {
    ERROR (PLUGIN_NAME ": %s: %s", eth0_address_file, strerror(errno));
    return 1;
  }
  fgets(p711_prov_eth0_mac, sizeof(p711_prov_eth0_mac), f_address);
  fclose(f_address);
  if ((lf = strchr(p711_prov_eth0_mac, '\n')) != NULL)
    *lf = '\0';
  printf("mac address = %s\n", p711_prov_eth0_mac);
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
    ERROR (PLUGIN_NAME ": %s", strerror(errno));
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
  snprintf(url, sizeof(url), "%s?mac=%s", baseurl, p711_prov_eth0_mac);
  //snprintf(url, sizeof(url), "%s", baseurl);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "P711Box " PLUGIN_VERSION);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, get_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)s);
  res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  if (res != 0) {
    INFO (PLUGIN_NAME ": %s: %s", baseurl, curl_easy_strerror(res));
    return 1;
  }
  return 0;
}

/* only compares small files */
static int file_compare(char *src, char *dst)
{
  char src_file[1024];
  int src_len;
  char dst_file[1024];
  int dst_len;
  FILE *f;

  if ((f = fopen(src, "r")) == NULL) {
    return -1;
  }
  src_len = fread(src_file, 1024, 1, f);
  fclose(f);

  if ((f = fopen(dst, "r")) == NULL) {
    return -1;
  }
  dst_len = fread(dst_file, 1024, 1, f);
  fclose(f);
  if (src_len != dst_len) {
    return(dst_len - src_len);
  }
  return strncmp(src_file, dst_file, src_len);
}

/* called by default every 10 seconds */
static int p711_prov_read (void)
{
static time_t last_read = 0;
  time_t now = time(NULL);
  struct string s;
  json_t *root;
  json_error_t error;
  int i;
  void *iter;

  //printf("%s\n", __func__);
  if (difftime(now, last_read) < 30) {
    return 0;
  }
  last_read = now;

  init_string(&s);
  if (p711_prov_request(&s) != 0) {
    free(s.ptr);
    return 0;
  }
  //printf("len=%d: %s\n", s.len, s.ptr);

  //root = json_loadb(s.ptr, s.len, JSON_DECODE_ANY, &error);
  root = json_loads(s.ptr, 0, &error);
  free(s.ptr);
  if (!root) {
    WARNING (PLUGIN_NAME ": %s line %d:%d: %s", error.source, error.line, error.column, error.text);
    printf("%s(%d): error\n", __FILE__, __LINE__);
    return 0;
  }
  //printf("%s(%d): root = %p\n", __FILE__, __LINE__, root);
  if (!json_is_object(root)) {
    WARNING (PLUGIN_NAME ": JSON root is not an object");
    return 0;
  }
  mkdir("/tmp/p711_prov", S_IRWXU);
  for (iter = json_object_iter(root); iter; iter = json_object_iter_next(root, iter)) {
    const char *key = json_object_iter_key(iter);
    json_t *value = json_object_iter_value(iter);

    //printf("Key: %s, ", key);
    if (!strcmp(key, "networks") && json_is_array(value)) {
      FILE *zt = fopen("/tmp/p711_prov/zerotier", "w");
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
      } else {
        WARNING (PLUGIN_NAME ": /tmp/p711_prov/zerotier: %s", strerror(errno));
      }
      if (file_compare("/tmp/p711_prov/zerotier", "/etc/config/zerotier")) {
        copy_file("/tmp/p711_prov/zerotier", "/etc/config/zerotier");
      }
      unlink("/tmp/p711_prov/zerotier");
    }
  }
  return (0);
}

void module_register (void)
{
  plugin_register_config ("p711_prov", p711_prov_config, config_keys, config_keys_num);
  plugin_register_init ("p711_prov", p711_prov_init);
  plugin_register_read ("p711_prov", p711_prov_read);
} /* void module_register */
