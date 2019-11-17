#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include "packet.h"
#include "http_util.h"
#include "block.h"

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

void usage() {
  printf("syntax: tcp_block <interface> <host>\n");
  printf("sample: tcp_block wlan0 test.gilgil.net\n");
}

int main(int argc, char* argv[]) {
  if (argc != 3) {
    usage();
    return -1;
  }

  const char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  const char* bad_host = argv[2];

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("----------%u bytes captured----------\n", header->caplen);
    
    const Eth_header *eth = (Eth_header*) packet;

    // check if ip packet
    if(ntohs(eth->ether_type) != ETHERTYPE_IP) continue;

    const IP_header *ip = (IP_header*)(eth + 1);

    // check if tcp packet
    if(ip->protocol != IPTYPE_TCP) continue;

    const TCP_header *tcp = (TCP_header*)((uint8_t*)ip + (ip->header_len << 2));

    const uint8_t *tcp_data = (uint8_t*)((uint8_t*)tcp + (tcp->hlen << 2));

    // check if http packet
    if(!is_http(tcp_data)) continue;

    const uint8_t *http = tcp_data;

    // check if bad_host
    char* host;
    int host_len;
    get_param(http, "Host", &host, &host_len);
    if(memcmp(bad_host, host, host_len)) continue;
    
    

  }

  pcap_close(handle);
  return 0;
}
