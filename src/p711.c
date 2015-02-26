/**
 * collectd - src/p711.c
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
#include <sys/stat.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <jansson.h>

static char p711_eth0_mac[20];

#define PLUGIN_NAME "p711"
#define PLUGIN_VERSION "1.0"

static const char *host = "udp.p711.net";
static const char *port = "7110";

/*
static void p711_submit (gauge_t snum, gauge_t mnum, gauge_t lnum)
{
  value_t values[3];
  value_list_t vl = VALUE_LIST_INIT;

  values[0].gauge = snum;
  values[1].gauge = mnum;
  values[2].gauge = lnum;

  vl.values = values;
  vl.values_len = STATIC_ARRAY_SIZE (values);

  sstrncpy (vl.host, hostname_g, sizeof (vl.host));
  sstrncpy (vl.plugin, "p711", sizeof (vl.plugin));
  sstrncpy (vl.type, "p711", sizeof (vl.type));

  plugin_dispatch_values (&vl);
}
*/

static int p711_process_action(char *buf)
{
  struct _namevalue {
    char *name;
    char *value;
  } nv[10];
  int i;

  memset(&nv[0], 0, sizeof(nv));
  for (i=0; i < 10 && *buf; i++) {
    nv[i].name = buf;
    while (*buf) if (*++buf == ':')  { *buf++ = 0; break; }
    nv[i].value = buf;
    while (*buf) if (*++buf == '\n') { *buf++ = 0; break; }
  }
  if (!strcmp(nv[0].name, "Action")) {
    if (!strcmp(nv[0].value, "Pong")) {
      printf("Pong\n");
    }
  }
  return 0;
}

/* list of hosts to talk to */
#define MAX_UDPHOSTS 10
#define UDPHOST_FREESLOT 0
#define UDPHOST_STARTING 1
#define UDPHOST_RUNNING  2
#define UDPHOST_STOPPING 3

static pthread_mutex_t udphost_lock = PTHREAD_MUTEX_INITIALIZER;
struct _udphost {
  char             ipaddr[INET6_ADDRSTRLEN];
  int              ai_family;
  int              ai_socktype;
  int              ai_protocol;
  struct sockaddr *ai_addr;
  socklen_t        ai_addrlen;
  int              status;
  int              seen;
} udphost[MAX_UDPHOSTS]; 

/*
 * The worker sends an UDP packet every 7 seconds to the host, and waits for an answer
 * The packet format is the mac address.
 */
static void *worker(void *parm)
{
  int id = (intptr_t) parm;
  int sfd;

  pthread_mutex_lock(&udphost_lock);
  INFO (PLUGIN_NAME ": worker started on id %d, (%s)", id, udphost[id].ipaddr);

  sfd = socket(udphost[id].ai_family, udphost[id].ai_socktype, udphost[id].ai_protocol);
  if (sfd != -1) {
    int tos = 0xb8;  // EF = Expedited Forwarding
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;

    if (setsockopt(sfd, IPPROTO_IP, IP_TOS,  &tos, sizeof(tos)) >= 0) {
      if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) >= 0) {
        if (connect(sfd, udphost[id].ai_addr, udphost[id].ai_addrlen) == -1) {
          WARNING (PLUGIN_NAME ": connect() for %s: %s", udphost[id].ipaddr, strerror(errno));
          close(sfd);
          sfd = -1;
        }
      } else {
        WARNING (PLUGIN_NAME ": setsockopt(SO_RCVTIMEO) for %s: %s", udphost[id].ipaddr, strerror(errno));
      }
    } else {
      WARNING (PLUGIN_NAME ": setsockopt(IP_TOS) for %s: %s", udphost[id].ipaddr, strerror(errno));
    }
  } else {
    WARNING (PLUGIN_NAME ": socket() for %s: %s", udphost[id].ipaddr, strerror(errno));
  }
  pthread_mutex_unlock(&udphost_lock);

  while (sfd != -1) {
    char buf[1500];
    int status;
    int len;

    sleep(5);
    //printf("sendto(%s): %s\n", udphost[id].ipaddr, p711_eth0_mac);
    snprintf(buf, sizeof(buf), "Action:Ping\nMAC:%s\n", p711_eth0_mac);
    if (sendto(sfd, buf,strlen(buf), 0, udphost[id].ai_addr, udphost[id].ai_addrlen) == -1) {
      WARNING (PLUGIN_NAME ": sendto(%s): %s", udphost[id].ipaddr, strerror(errno));
      close(sfd);
      sfd = -1;
      continue;
    }
    while ((len = recvfrom(sfd, buf, sizeof(buf), 0, NULL, NULL)) == -1 && errno == EINTR) 
      ;
    if (len == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        pthread_mutex_lock(&udphost_lock);
        status = udphost[id].status;
        pthread_mutex_unlock(&udphost_lock);
        if (status == UDPHOST_STOPPING) {
          close(sfd);
          sfd = -1;
        }
      } else {
        WARNING (PLUGIN_NAME ": recvfrom(%s): %s", udphost[id].ipaddr, strerror(errno));
        close(sfd);
        sfd = -1;
      }
      continue;
    }
    buf[len] = 0;
    //printf("recvfrom(%s): %s\n", udphost[id].ipaddr, buf);
    p711_process_action(buf);
  }

  pthread_mutex_lock(&udphost_lock);
  INFO (PLUGIN_NAME ": worker stopped on id %d, (%s)", id, udphost[id].ipaddr);
  free(udphost[id].ai_addr);
  udphost[id].status = UDPHOST_FREESLOT;
  udphost[id].ipaddr[0] = '\0';
  pthread_mutex_unlock(&udphost_lock);
  return NULL;
}

/* 
 * called by default every 10 seconds.
 * ask DNS for the actual ip addresses for udp.p711.net
 */
static int p711_read (void)
{
  struct addrinfo  ai_hints;
  struct addrinfo *ai_list, *ai_ptr;
  int              ai_return;

  memset (&ai_hints, '\0', sizeof (ai_hints));
  ai_hints.ai_flags    = 0;
#ifdef AI_ADDRCONFIG
  ai_hints.ai_flags   |= AI_ADDRCONFIG;
#endif
  ai_hints.ai_family   = AF_UNSPEC;
  ai_hints.ai_socktype = SOCK_DGRAM;
  ai_hints.ai_protocol = 0;

  if ((ai_return = getaddrinfo (host, port, &ai_hints, &ai_list)) != 0) {
    char errbuf[1024];
    ERROR (PLUGIN_NAME ": getaddrinfo (%s, %s): %s", host, port, 
        (ai_return == EAI_SYSTEM)
        ? sstrerror (errno, errbuf, sizeof (errbuf))
        : gai_strerror (ai_return));
    return 0;
  }

  pthread_mutex_lock(&udphost_lock);
  for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
    char ipaddr[INET6_ADDRSTRLEN];
    int i, found;
    int freeslot = -1;

    if (!inet_ntop(ai_ptr->ai_family, &((struct sockaddr_in *)ai_ptr->ai_addr)->sin_addr, ipaddr, INET6_ADDRSTRLEN)) {
      ERROR (PLUGIN_NAME ": inet_ntop: %s", strerror(errno));
      continue;
    }
    //printf("ip addrs: %s\n", ipaddr);

    /* got an ip address, check if we're already running on this one, or insert and start worker */
    for (i=0, found=0; i < MAX_UDPHOSTS && !found; i++) {
      if (freeslot == -1 && udphost[i].status == UDPHOST_FREESLOT) {
        freeslot = i; /* remember this as our free slot to insert in */
      }
      if (strcmp(udphost[i].ipaddr, ipaddr)) {
        continue; /* not this address, skip this */
      }
      udphost[i].seen = 1;
      found = 1;
    }
    if (!found && freeslot != -1) { /* new host found in DNS, start worker on it */
      pthread_t th;
      pthread_attr_t th_attr;

      pthread_attr_init (&th_attr);
      pthread_attr_setdetachstate (&th_attr, PTHREAD_CREATE_DETACHED);
      udphost[freeslot].ai_addr     = malloc(ai_ptr->ai_addrlen); /* copy sock info */
      udphost[freeslot].ai_family   = ai_ptr->ai_family;
      udphost[freeslot].ai_socktype = ai_ptr->ai_socktype;
      udphost[freeslot].ai_protocol = ai_ptr->ai_protocol;
      udphost[freeslot].ai_addrlen  = ai_ptr->ai_addrlen;
      memcpy(udphost[freeslot].ai_addr, ai_ptr->ai_addr, ai_ptr->ai_addrlen);
      if (plugin_thread_create (&th, &th_attr, worker, (void *) (intptr_t) freeslot)) {
        char errbuf[1024];
        WARNING (PLUGIN_NAME ": pthread_create failed: %s", sstrerror (errno, errbuf, sizeof (errbuf)));
        free(udphost[freeslot].ai_addr);
        continue;
      }
      strncpy(udphost[freeslot].ipaddr, ipaddr, sizeof(udphost[freeslot].ipaddr));
      udphost[freeslot].status = UDPHOST_STARTING;
      udphost[freeslot].seen = 1;
      NOTICE (PLUGIN_NAME ": found new host %s in DNS record, starting worker", udphost[freeslot].ipaddr);
    }
  }
/*
  if (rand() % 3 == 0) {
    udphost[0].seen = 0;
  }
*/
  /* See if hosts disappeared from the DNS record - stop the worker on it */
  { 
    int i;
    for (i=0; i < MAX_UDPHOSTS; i++) {
      if (udphost[i].seen) {
        udphost[i].seen = 0;
        continue;
      }
      if (udphost[i].status != UDPHOST_FREESLOT) {
        udphost[i].status = UDPHOST_STOPPING; /* worker will exit when seeing this */
        NOTICE (PLUGIN_NAME ": host %s disappeared from DNS record, removing worker", udphost[i].ipaddr);
      }
    }
  }
  pthread_mutex_unlock(&udphost_lock);
  freeaddrinfo (ai_list);

  return 0;
}

static int p711_init (void)
{
  char *lf;
  char *eth0_address_file = "/sys/class/net/eth0/address";
  FILE *fd;

  fd = fopen(eth0_address_file, "r");
  if (!fd) {
    ERROR (PLUGIN_NAME ": %s: %s", eth0_address_file, strerror(errno));
    return 1;
  }
  fgets(p711_eth0_mac, sizeof(p711_eth0_mac), fd);
  fclose(fd);
  if ((lf = strchr(p711_eth0_mac, '\n')) != NULL)
    *lf = '\0';
  INFO (PLUGIN_NAME ": using %s", p711_eth0_mac);
  return 0;
}

void module_register (void)
{
  plugin_register_init ("p711", p711_init);
  plugin_register_read ("p711", p711_read);
  //plugin_register_write ("p711", p711_write, NULL);
} /* void module_register */

