#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "packet.h"
#include "packet_util.h"

int send_packet(const char * dev, uint8_t* pkt, int packet_len){
	// send packet (https://blog.pages.kr/290)
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *fp;
	fp = pcap_open_live(dev, 65536, 0, 1000, errbuf);
	int e=pcap_sendpacket(fp, pkt, packet_len);
	if(e) perror(errbuf);
	return e;
}

void calculate_IP_checksum(IP_header* ip){
	int i;

	ip->checksum = 0;
	uint32_t sum = 0;

	for(i = 0; i < ip->header_len << 2; i += 2)
		sum += *(uint16_t*)((uint8_t*)ip + i);

	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);

	sum = ~sum;

	ip->checksum = (uint16_t)sum;
}

void calculate_TCP_checksum(const IP_header* ip, TCP_header* tcp, int tcp_length){
	int i;

	tcp->checksum = 0;
	uint32_t sum = 0;

	for(i = 0; i < tcp_length; i += 2)
		sum += *(uint16_t*)((uint8_t*)tcp + i);

	if(tcp_length % 2 == 1)
		sum += *((uint8_t*)tcp + tcp_length - 1);

	sum += ip->src_ip >> 16;
	sum += ip->src_ip & 0xffff;
	sum += ip->dst_ip >> 16;
	sum += ip->dst_ip & 0xffff;

	sum += htons(ip->protocol);
	sum += htons(tcp_length);

	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);

	sum = ~sum;

	tcp->checksum = (uint16_t)sum;

}
