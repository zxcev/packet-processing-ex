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

void dispatch_handler(u_char *temp1,
                      // description, time info
                      const struct pcap_pkthdr *header,
                      // packet's raw data(l2 frame)
                      const u_char *pkt_data) {
  u_int i = 0;

  // print pkt timestamp and pkt len
  printf("%ld:%ld (%u)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

  struct ether_header_t *p_ether = (struct ether_header_t *)pkt_data;

  printf("dest mac: %02X-%02X-%02X-%02X-%02X-%02X, type: %04X\n",
         p_ether->dst_mac[0], p_ether->dst_mac[1], p_ether->dst_mac[2],
         p_ether->dst_mac[3], p_ether->dst_mac[4], p_ether->dst_mac[5],
         ntohs(p_ether->type));
  printf("src mac: %02X-%02X-%02X-%02X-%02X-%02X, type: %04X\n",
         p_ether->src_mac[0], p_ether->src_mac[1], p_ether->src_mac[2],
         p_ether->src_mac[3], p_ether->src_mac[4], p_ether->src_mac[5],
         ntohs(p_ether->type));

  // print the packet
  for (i = 1; (i < header->caplen + 1); i++) {
    printf("%.2x ", pkt_data[i - 1]);
    if ((i % LINE_LEN) == 0) {
      printf("\n");
    }
  }
  printf("\n\n");
}

int main() {
  pcap_t *fp;
  char errbuf[PCAP_ERRBUF_SIZE];

  if ((fp = pcap_open_offline("SampleTrace/ip-fragments.pcap", errbuf)) ==
      NULL) {
    fprintf(stderr, "\nUnable to open the file.");
    return -1;
  }

  // start the capture
  pcap_loop(fp, 0, dispatch_handler, NULL);

  pcap_close(fp);

  return 0;
}
