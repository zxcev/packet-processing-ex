#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void packet_handler(u_char *params,
                    // description, time info
                    const struct pcap_pkthdr *header,
                    // packet's raw data(l2 frame)
                    const u_char *pkt_data) {
  struct tm *ltime;
  char timestr[16];
  time_t local_tv_sec;

  // convert the timestamp to readable format
  local_tv_sec = header->ts.tv_sec;
  ltime = localtime(&local_tv_sec);
  strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
  printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);
}

int main() {
  // pcap interface type
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int inum;
  int i = 0;
  pcap_t *adhandle;
  char errbuf[PCAP_ERRBUF_SIZE];

  // load npcap and its functions

  // retrieve the device list
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }

  // print the list
  for (d = alldevs; d; d = d->next) {
    printf("%d. %s", ++i, d->name);
    if (d->description) {
      printf(" (%s)\n", d->description);
    } else {
      printf(" (no description available)\n");
    }
  }

  // input nth of NIC
  printf("Enter the interface number (1-%d): ", i);
  scanf("%d", &inum);

  // check if it is validated NIC number
  if (inum < 1 || inum > i) {
    printf("\ninterface number out of range.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }

  // jump to the selected adapter
  for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
    ;

  // open the device
  // open the adapter
  if ((adhandle =
           pcap_open_live(d->name, // name of the device
                          65536,   // portion of the packet to capture
                                   // 65536 grants that the whole packet will be
                                   // captured on all the MACs.
                          1, // promiscous mode(nonzero) - network로 유입되는
                             // 것을 나한테 오는 것이던 아니던 다 읽음
                          1000, // read timeout
                          errbuf)) == NULL) {
    fprintf(stderr, "\nUnable to open the adapter. %s is not supported",
            d->name);
    pcap_freealldevs(alldevs);
    return -1;
  }

  printf("\nlistening on %s...\n", d->description);

  // at this point, we don't need anymore the device list
  // release
  pcap_freealldevs(alldevs);

  // start the capture
  pcap_loop(adhandle, 0, packet_handler, NULL);

  return 0;
}
