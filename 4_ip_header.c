#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define LINE_LEN 16

#pragma pack(push, 1)
struct ether_header_t {
  unsigned char dst_mac[6];
  unsigned char src_mac[6];
  unsigned short type;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ip_header_t {
  unsigned char ver_ihl;
  unsigned char tos;
  unsigned short length;
  unsigned short id;
  unsigned short frag_offset;
  unsigned char ttl;
  unsigned char protocol;
  unsigned short checksum;
  unsigned char src_ip[4];
  unsigned char dst_ip[4];
};
#pragma pack(pop)

void packet_handler(u_char *temp1,
                    // description, time info
                    const struct pcap_pkthdr *header,
                    // packet's raw data(l2 frame)
                    const u_char *pkt_data) {

  struct ether_header_t *p_ether = (struct ether_header_t *)pkt_data;
  if (p_ether->type != ntohs(0x0800)) {
    perror("it's not ipv4 protocol");
    return;
  }

  struct ip_header_t *p_ip_header =
      (struct ip_header_t *)(pkt_data + sizeof(struct ether_header_t));
  printf("IPv%d, ihl: %d, total length: %d\n",
         (p_ip_header->ver_ihl & 0xF0) >> 4, (p_ip_header->ver_ihl & 0x0F) * 4,
         ntohs(p_ip_header->length));

  printf("TTL: %d, Protocol: %02X, Checksum: %04X\n", p_ip_header->ttl,
         p_ip_header->protocol, ntohs(p_ip_header->checksum));

  printf("src ip: %d.%d.%d.%d -> dst ip: %d.%d.%d.%d\n", p_ip_header->src_ip[0],
         p_ip_header->src_ip[1], p_ip_header->src_ip[2], p_ip_header->src_ip[3],
         p_ip_header->dst_ip[0], p_ip_header->dst_ip[1], p_ip_header->dst_ip[2],
         p_ip_header->dst_ip[3]);

  printf("dest mac: %02X-%02X-%02X-%02X-%02X-%02X, type: %04X\n",
         p_ether->dst_mac[0], p_ether->dst_mac[1], p_ether->dst_mac[2],
         p_ether->dst_mac[3], p_ether->dst_mac[4], p_ether->dst_mac[5],
         ntohs(p_ether->type));
  printf("src mac: %02X-%02X-%02X-%02X-%02X-%02X, type: %04X\n",
         p_ether->src_mac[0], p_ether->src_mac[1], p_ether->src_mac[2],
         p_ether->src_mac[3], p_ether->src_mac[4], p_ether->src_mac[5],
         ntohs(p_ether->type));

  // // print the packet
  // for (i = 1; (i < header->caplen + 1); i++) {
  //   printf("%.2x ", pkt_data[i - 1]);
  //   if ((i % LINE_LEN) == 0) {
  //     printf("\n");
  //   }
  // }
  // printf("\n\n");
}

int main() {
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int inum;
  int i = 0;
  pcap_t *adhandle;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    return -1;
  }

  for (d = alldevs; d; d = d->next) {
    printf("%d. %s", ++i, d->name);
    if (d->description) {
      printf(" (%s)\n", d->description);
    } else {
      printf("(no description available)\n");
    }
  }

  if (i == 0) {
    printf("\nNo NIC found.");
    return -1;
  }

  printf("Enter the NIC number (1-%d): ", i);
  scanf("%d", &inum);

  if (inum < 0 || inum > i) {
    perror("\nNIC number out of range");
    pcap_freealldevs(alldevs);
    return -1;
  }

  for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
    ;

  if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
    fprintf(stderr,
            "\nUnable to open the adapter. %s is not supported by Npcap\n",
            d->name);
    pcap_freealldevs(alldevs);
    return -1;
  }

  printf("\nlistening on %s...\n", d->description);

  pcap_freealldevs(alldevs);
  pcap_loop(adhandle, 0, packet_handler, NULL);

  pcap_close(adhandle);

  return 0;
}
