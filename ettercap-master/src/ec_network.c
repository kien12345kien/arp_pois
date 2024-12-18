#include <ec.h>
#include <ec_capture.h>
#include <ec_decode.h>
#include <ec_queue.h>
#include <ec_network.h>
#include <ec_threads.h>

#include <pcap.h>
#include <libnet.h>
#if !defined(OS_WINDOWS)
#include <ifaddrs.h>
#endif

#define PCAP_TIMEOUT 1

struct source_entry {
   struct iface_env iface;
   LIST_ENTRY(source_entry) next;
};

/* globals */
static LIST_HEAD(,source_entry) sources_list;
static pthread_mutex_t sl_mutex = PTHREAD_MUTEX_INITIALIZER;
#define SOURCES_LIST_LOCK     do{ pthread_mutex_lock(&sl_mutex); }while(0)
#define SOURCES_LIST_UNLOCK   do{ pthread_mutex_unlock(&sl_mutex); }while(0)

/* protos */
static void close_network();
static void pcap_winit(pcap_t *pcap);
static void source_print(struct iface_env *source);
static int source_init(char *name, struct iface_env *source, bool primary, bool live);
static void source_close(struct iface_env *iface);
static int secondary_sources_init(char **sources);
static void close_secondary_sources(void);
static void l3_init(void);
static void l3_close(void);

/* the code */

void network_init()
{
   char *iface;

   DEBUG_MSG("init_network");

   EC_GBL_PCAP->snaplen = UINT16_MAX;
   
   if(EC_GBL_OPTIONS->read) {
      source_init(EC_GBL_OPTIONS->pcapfile_in, EC_GBL_IFACE, true, false);
      source_print(EC_GBL_IFACE);
   } else {
      iface = EC_GBL_OPTIONS->iface ? EC_GBL_OPTIONS->iface : (EC_GBL_OPTIONS->iface = capture_default_if());
      ON_ERROR(iface, NULL, "No suitable interface found...");
      source_init(iface, EC_GBL_IFACE, true, true);
      source_print(EC_GBL_IFACE);
      if(EC_GBL_SNIFF->type == SM_BRIDGED) {
         source_init(EC_GBL_OPTIONS->iface_bridge, EC_GBL_BRIDGE, true, true);
         source_print(EC_GBL_BRIDGE);
         if(EC_GBL_BRIDGE->dlt != EC_GBL_IFACE->dlt)
            FATAL_ERROR("Can't bridge interfaces of different types");
      }
   }

   if(get_decoder(LINK_LAYER, EC_GBL_IFACE->dlt) == NULL) {
      if(EC_GBL_OPTIONS->read)
         FATAL_ERROR("Dump file not supported (%s)", pcap_datalink_val_to_description(EC_GBL_PCAP->dlt));
      else
         FATAL_ERROR("Interface \"%s\" not supported (%s)", EC_GBL_OPTIONS->iface, pcap_datalink_val_to_description(EC_GBL_PCAP->dlt));
   }
   
   if(EC_GBL_OPTIONS->write)
      pcap_winit(EC_GBL_IFACE->pcap);
   
   /* determine alignment margin and allocate packet buffer per interface */
   EC_GBL_PCAP->align = get_alignment(EC_GBL_PCAP->dlt);
   SAFE_CALLOC(EC_GBL_IFACE->pbuf, UINT16_MAX + EC_GBL_PCAP->align + 256, sizeof(char));
   if (!EC_GBL_OPTIONS->read && EC_GBL_SNIFF->type == SM_BRIDGED)
      SAFE_CALLOC(EC_GBL_BRIDGE->pbuf, UINT16_MAX + EC_GBL_PCAP->align + 256, sizeof(char));

   if(EC_GBL_OPTIONS->secondary) {
      secondary_sources_init(EC_GBL_OPTIONS->secondary);
      atexit(close_secondary_sources);
   }

   /* Layer 3 handlers initialization */
   if(!EC_GBL_OPTIONS->unoffensive)
      l3_init();
      
   atexit(close_network);
}

static void close_network()
{
   pcap_close(EC_GBL_IFACE->pcap);
   SAFE_FREE(EC_GBL_IFACE->pbuf);
   if(EC_GBL_SNIFF->type == SM_BRIDGED) {
      pcap_close(EC_GBL_BRIDGE->pcap);
      SAFE_FREE(EC_GBL_BRIDGE->pbuf);
   }

   if(EC_GBL_OPTIONS->write)
      pcap_dump_close(EC_GBL_PCAP->dump);

   libnet_destroy(EC_GBL_IFACE->lnet);
   libnet_destroy(EC_GBL_BRIDGE->lnet);

   DEBUG_MSG("ATEXIT: close_network");
}

static void pcap_winit(pcap_t *pcap)
{
   pcap_dumper_t *pdump;
   pdump = pcap_dump_open(pcap, EC_GBL_OPTIONS->pcapfile_out);
   ON_ERROR(pdump, NULL, "pcap_dump_open: %s", pcap_geterr(pcap));
   EC_GBL_PCAP->dump = pdump;
}

static void source_print(struct iface_env *source)
{
   char strbuf[256];
   struct net_list *ip6;

   if(source->is_live) {
      USER_MSG("Listening on:\n");
      USER_MSG("%6s -> %s\n", source->name, mac_addr_ntoa(source->mac, strbuf));
      if(source->has_ipv4) {
         USER_MSG("\t  %s/", ip_addr_ntoa(&source->ip, strbuf));
         USER_MSG("%s\n", ip_addr_ntoa(&source->netmask, strbuf));
      }
      if(source->has_ipv6) {
         LIST_FOREACH(ip6, &source->ip6_list, next) {
            USER_MSG("\t  %s/%d\n", ip_addr_ntoa(&ip6->ip, strbuf), ip6->prefix);
         }
         USER_MSG("\n");
      } else {
         USER_MSG("\n\n");
      }
   } else {
      USER_MSG("Reading from %s\n", source->name);
   }

}

static int source_init(char *name, struct iface_env *source, bool primary, bool live)
{
   int ret;
   pcap_t *pcap = NULL;
   libnet_t *lnet = NULL;
   struct bpf_program bpf;
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
   char lnet_errbuf[LIBNET_ERRBUF_SIZE];
   int snaplen;

   struct libnet_ether_addr *mac;
   struct sockaddr_in *sa4;
   struct sockaddr_in6 *sa6;
   struct net_list *ip6;

#if !defined(OS_WINDOWS)
  struct ifaddrs *ifaddrs, *ifaddr;
#endif

   DEBUG_MSG("source_init %s", name);

   BUG_IF(source == NULL);

   /* ===pcap initialization=== */
   if(live) {
      pcap = pcap_open_live(name, EC_GBL_PCAP->snaplen, EC_GBL_PCAP->promisc, PCAP_TIMEOUT, pcap_errbuf);
      if(pcap == NULL) {
         if(primary)
            ON_ERROR(pcap, NULL, "pcap_open_live: %s", pcap_errbuf);
         else
            return -E_INITFAIL;
      }
   } else {
      /* secondary sources must not be offline */
      if(!primary)
         return -E_NOTHANDLED;

      struct stat st;
      int stat_result;
      FILE* pcap_file_h;

      pcap = pcap_open_offline(name, pcap_errbuf);
      ON_ERROR(pcap, NULL, "pcap_open_offline: %s", pcap_errbuf);

      pcap_file_h = pcap_file(pcap);
      ON_ERROR(pcap_file_h, 0, "pcap_fileno returned an invalid file handle");

      stat_result = fstat(fileno(pcap_file_h), &st);
      ON_ERROR(stat_result, -1, "fstat failed.");

      EC_GBL_PCAP->dump_size = st.st_size;
   }
   source->dlt = pcap_datalink(pcap);
   if(primary)
      EC_GBL_PCAP->dlt = source->dlt;
   if(source->dlt == DLT_IEEE802_11) {
      DEBUG_MSG("Wireless monitor mode used, switching to unoffensive mode");
      source->unoffensive = 1;
      if(primary)
         EC_GBL_OPTIONS->unoffensive = 1;
   }
   if(!strcmp(name, "lo")) {
      DEBUG_MSG("Loopback interface used, switching to unoffensive mode");
      source->unoffensive = 1;
      if(primary)
         EC_GBL_OPTIONS->unoffensive = 1;
   }

   if(EC_GBL_PCAP->filter && strcmp(EC_GBL_PCAP->filter, "") && live) {
      u_int net, mask;
      if(pcap_lookupnet(name, &net, &mask, pcap_errbuf) == -1)
         ERROR_MSG("%s - %s", name, pcap_errbuf);
      if(pcap_compile(pcap, &bpf, EC_GBL_PCAP->filter, 1, mask) < 0)
         ERROR_MSG("Wrong pcap filter: %s - %s", name, pcap_geterr(pcap));
      if(pcap_setfilter(pcap, &bpf) == 1)
         ERROR_MSG("Cannot set pcap filter: %s - %s", name, pcap_geterr(pcap));
   }

   snaplen = pcap_snapshot(pcap);
   DEBUG_MSG("requested snaplen for %s: %d, assigned snaplen: %d", name, EC_GBL_PCAP->snaplen, snaplen);
   if(primary)
      EC_GBL_PCAP->snaplen = snaplen;
   source->pcap = pcap;

   SAFE_STRDUP(source->name, name);

   if(live) {
      source->is_live = 1;
   } else {
      source->is_ready = 1;
      return E_SUCCESS;
   }

   if(!EC_GBL_OPTIONS->unoffensive && !source->unoffensive) {
      lnet = libnet_init(LIBNET_LINK_ADV, name, lnet_errbuf);
      ON_ERROR(lnet, NULL, "libnet_init: %s", lnet_errbuf);

      mac = libnet_get_hwaddr(lnet);
      memcpy(&source->mac, mac, MEDIA_ADDR_LEN);
   }

   source->lnet = lnet;

   source->mtu = get_iface_mtu(name);
#if defined(OS_WINDOWS)
  pcap_if_t *dev;

  for (dev = (pcap_if_t *)EC_GBL_PCAP->ifs; dev; dev = dev->next) {
      if(strcmp(dev->name, name))
        continue;

      if(dev->addresses->addr->sa_family == AF_INET) {
        sa4 = (struct sockaddr_in*) dev->addresses->addr;

        ip_addr_init(&source->ip, AF_INET, (u_char*)&sa4->sin_addr);
        if(EC_GBL_OPTIONS->netmask) {
            if(ip_addr_pton(EC_GBL_OPTIONS->netmask, &source->netmask) != E_SUCCESS)
              FATAL_ERROR("Invalid netmask %s", EC_GBL_OPTIONS->netmask);
        } else {
            sa4 = (struct sockaddr_in*) dev->addresses->netmask;
            ip_addr_init(&source->netmask, AF_INET, (u_char*)&sa4->sin_addr);
        }
        ip_addr_get_network(&source->ip, &source->netmask, &source->network);
        source->has_ipv4 = 1;
      }
      else if(dev->addresses->addr->sa_family == AF_INET6) {
        SAFE_CALLOC(ip6, 1, sizeof(*ip6));
        sa6 = (struct sockaddr_in6*) dev->addresses->addr;
        ip_addr_init(&ip6->ip, AF_INET6, (u_char*)&sa6->sin6_addr);

        sa6 = (struct sockaddr_in6*) dev->addresses->netmask;
        ip_addr_init(&ip6->netmask, AF_INET6, (u_char*)&sa6->sin6_addr);
        ip_addr_get_network(&ip6->ip, &ip6->netmask, &ip6->network);
        ip6->prefix = ip_addr_get_prefix(&ip6->netmask);
        LIST_INSERT_HEAD(&source->ip6_list, ip6, next);
        source->has_ipv6 = 1;
      }
  }

#else
   ret = getifaddrs(&ifaddrs);
   ON_ERROR(ret, -1, "getifaddrs: %s", strerror(errno));

   for(ifaddr = ifaddrs; ifaddr; ifaddr = ifaddr->ifa_next) {
      if (ifaddr->ifa_addr == NULL)
         continue;
      if(strcmp(ifaddr->ifa_name, name))
         continue;

      if(ifaddr->ifa_addr->sa_family == AF_INET) {
         sa4 = (struct sockaddr_in*)ifaddr->ifa_addr;
         ip_addr_init(&source->ip, AF_INET, (u_char*)&sa4->sin_addr);
         if(EC_GBL_OPTIONS->netmask) {
            if(ip_addr_pton(EC_GBL_OPTIONS->netmask, &source->netmask) != E_SUCCESS)
               FATAL_ERROR("Invalid netmask %s", EC_GBL_OPTIONS->netmask);
         } else {
            sa4 = (struct sockaddr_in*)ifaddr->ifa_netmask;
            ip_addr_init(&source->netmask, AF_INET, (u_char*)&sa4->sin_addr);
         }
         ip_addr_get_network(&source->ip, &source->netmask, &source->network);
         source->has_ipv4 = 1;
      } else if(ifaddr->ifa_addr->sa_family == AF_INET6) {
         SAFE_CALLOC(ip6, 1, sizeof(*ip6));
         sa6 = (struct sockaddr_in6*)ifaddr->ifa_addr;
         ip_addr_init(&ip6->ip, AF_INET6, (u_char*)&sa6->sin6_addr);
         sa6 = (struct sockaddr_in6*)ifaddr->ifa_netmask;
         ip_addr_init(&ip6->netmask, AF_INET6, (u_char*)&sa6->sin6_addr);
         ip_addr_get_network(&ip6->ip, &ip6->netmask, &ip6->network);
         ip6->prefix = ip_addr_get_prefix(&ip6->netmask);
         LIST_INSERT_HEAD(&source->ip6_list, ip6, next);
         source->has_ipv6 = 1;
      }
   }

   freeifaddrs(ifaddrs);
#endif  /* OS_WINDOWS */

   source->is_ready = 1;

   return E_SUCCESS;
}

static void source_close(struct iface_env *iface)
{
#ifdef WITH_IPV6
   struct net_list *n;
#endif

   iface->is_ready = 0;

   if(iface->pcap != NULL)
      pcap_close(iface->pcap);

   if(iface->lnet != NULL)
      libnet_destroy(iface->lnet);
  
#ifdef WITH_IPV6 
   LIST_FOREACH(n, &iface->ip6_list, next) {
      LIST_REMOVE(n, next);
      SAFE_FREE(n);
   }
#endif

   SAFE_FREE(iface->name);
   memset(iface, 0, sizeof(*iface));
}

static int secondary_sources_init(char **sources)
{
   struct source_entry *se;
   int n = 0;

   SOURCES_LIST_LOCK;

   for(n = 0; sources[n] != NULL; n++) {
      SAFE_CALLOC(se, 1, sizeof(*se));

      /* secondary interfaces are always live */
      source_init(sources[n], &se->iface, true, false);
      if(se->iface.is_ready)
         LIST_INSERT_HEAD(&sources_list, se, next);
      else 
         SAFE_FREE(se);
   }

   SOURCES_LIST_UNLOCK;

   return n;
}

void secondary_sources_foreach(void (*callback)(struct iface_env*))
{
    struct source_entry *se;

    SOURCES_LIST_LOCK;

    LIST_FOREACH(se, &sources_list, next) {
        callback(&se->iface);
    }

    SOURCES_LIST_UNLOCK;
}

static void close_secondary_sources(void)
{
   struct source_entry *se;

   SOURCES_LIST_LOCK;

   LIST_FOREACH(se, &sources_list, next) {
      LIST_REMOVE(se, next);
      source_close(&se->iface);
      SAFE_FREE(se);
   }

   SOURCES_LIST_UNLOCK;
}

static void l3_init(void)
{
   libnet_t *l4;
#ifdef WITH_IPV6
   libnet_t *l6;
#endif
#ifdef OS_WINDOWS
   char *name = EC_GBL_OPTIONS->iface;
#else
   char *name = NULL;
#endif


   char lnet_errbuf[LIBNET_ERRBUF_SIZE];

   DEBUG_MSG("l3_init");

   /* open the socket at layer 3 */
   l4 = libnet_init(LIBNET_RAW4_ADV, name, lnet_errbuf);               
   if (l4 == NULL) {
      DEBUG_MSG("send_init: libnet_init(LIBNET_RAW4_ADV) failed: %s", lnet_errbuf);
      USER_MSG("Libnet failed IPv4 initialization. Don't send IPv4 packets.\n");
   }

   EC_GBL_LNET->lnet_IP4 = l4;               

#ifdef WITH_IPV6
   /* open the socket at layer 3 for IPv6 */
   l6 = libnet_init(LIBNET_RAW6_ADV, name, lnet_errbuf);
   if(l6 == NULL) {
      DEBUG_MSG("%s: libnet_init(LIBNET_RAW6_ADV) failed: %s", __func__, lnet_errbuf);
      USER_MSG("Libnet failed IPv6 initialization. Don't send IPv6 packets.\n");
   }
   
   EC_GBL_LNET->lnet_IP6 = l6;
#endif

   atexit(l3_close);
}

static void l3_close(void)
{
   if(EC_GBL_LNET->lnet_IP4)
      libnet_destroy(EC_GBL_LNET->lnet_IP4);
#ifdef WITH_IPV6
   if(EC_GBL_LNET->lnet_IP6)
      libnet_destroy(EC_GBL_LNET->lnet_IP6);
#endif
   
   DEBUG_MSG("ATEXIT: send_closed");
}

struct iface_env* iface_by_mac(u_int8 mac[MEDIA_ADDR_LEN])
{
   struct source_entry *se;

   SOURCES_LIST_LOCK;

   LIST_FOREACH(se, &sources_list, next) {
      if(!memcmp(se->iface.mac, mac, MEDIA_ADDR_LEN)) {
         SOURCES_LIST_UNLOCK;
         return &se->iface;
      }
   }

   SOURCES_LIST_UNLOCK;
   return NULL;
}