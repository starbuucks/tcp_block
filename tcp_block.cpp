#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "packet.h"
#include "packet_util.h"
#include "tcp_block.h"

#define calculate_IP_hlen(iphlen, tcphlen) (((int)(iphlen) << 2) + ((int)(tcphlen) << 2))

using namespace std;

char block_msg[] = "HTTP/1.0 200 OK\x0d\x0aContent-Length: 214\x0d\x0aContent-Type: text/html\x0d\x0a\x0d\x0a<html><head><meta http-equiv=\"pragma\" content=\"no-cache\"><meta http-equiv=\"refresh\" content=\"0;url=\'http://www.warning.or.kr/i1.html\'\"></head></html>";

void forward_block(u_char* pkt, IP_header* ip, TCP_header* tcp, char* tcp_data, int new_data_len){
	int tcp_data_len = ntohs(ip->total_len) - tcp->hlen << 2;

	ip->total_len = htons(calculate_IP_hlen(ip->header_len, TCPHLEN_MIN) + new_data_len);

	calculate_IP_checksum(ip);

	tcp->seq_num = htonl(ntohl(tcp->seq_num) + tcp_data_len);
	
	tcp->hlen = TCPHLEN_MIN;

	if(new_data_len != 0)
		memcpy((u_char*)tcp + tcp->hlen, tcp_data, new_data_len);

	calculate_TCP_checksum(ip, tcp, tcp->hlen << 2 + new_data_len);
}

void backward_block(u_char* pkt, IP_header* ip, TCP_header* tcp, char* tcp_data, int tcp_data_len){
	MAC mac_tmp;
	mac_tmp = ((Eth_header*)pkt)->dst_mac;
	((Eth_header*)pkt)->dst_mac = ((Eth_header*)pkt)->src_mac;
	((Eth_header*)pkt)->src_mac = mac_tmp;

	uint32_t newseq = htonl(ntohl(tcp->seq_num) + ntohs(ip->total_len) - calculate_IP_hlen(ip->header_len, tcp->hlen));
	uint32_t tmp;
	tmp = ip->src_ip;
	ip->src_ip = ip->dst_ip;
	ip->dst_ip = tmp;

	ip->total_len = htons(calculate_IP_hlen(ip->header_len, TCPHLEN_MIN) + tcp_data_len);

	calculate_IP_checksum(ip);

	tmp = tcp->src_port;
	tcp->src_port = tcp->dst_port;
	tcp->dst_port = tmp;

	tcp->seq_num = tcp->ack_num;
	tcp->ack_num = newseq;

	tcp->hlen = TCPHLEN_MIN;
	tcp->window = 0;

	if(tcp_data_len != 0)
		memcpy((u_char*)tcp + (tcp->hlen << 2), tcp_data, tcp_data_len);

	calculate_TCP_checksum(ip, tcp, (tcp->hlen << 2) + tcp_data_len);
}

int forward_RST(const char * dev, u_char* pkt, int pkt_len){

	u_char* new_pkt = (u_char*)malloc(pkt_len);
	memcpy(new_pkt, pkt, pkt_len);

	IP_header* ip = (IP_header*)(new_pkt + sizeof(Eth_header));
	TCP_header* tcp = (TCP_header*)((u_char*)ip + (ip->header_len << 2));

	tcp->flag = TCPFLAG_RST;

	forward_block(new_pkt, ip, tcp, 0, 0);

	int e = send_packet(dev, (uint8_t*)new_pkt, sizeof(Eth_header) + ntohs(ip->total_len));

	free(new_pkt);

	return e;
}

int forward_FIN(const char * dev, u_char* pkt, int pkt_len){

	u_char* new_pkt = (u_char*)malloc(pkt_len);
	memcpy(new_pkt, pkt, pkt_len);

	IP_header* ip = (IP_header*)(new_pkt + sizeof(Eth_header));
	TCP_header* tcp = (TCP_header*)((u_char*)ip + (ip->header_len << 2));

	tcp->flag = TCPFLAG_FIN | TCPFLAG_PSH | TCPFLAG_ACK;

	forward_block(new_pkt, ip, tcp, "blocked", 7);

	int e = send_packet(dev, (uint8_t*)new_pkt, sizeof(Eth_header) + ntohs(ip->total_len));

	free(new_pkt);

	return e;
}

int backward_RST(const char * dev, u_char* pkt, int pkt_len){

	u_char* new_pkt = (u_char*)malloc(pkt_len);
	memcpy(new_pkt, pkt, pkt_len);

	IP_header* ip = (IP_header*)(new_pkt + sizeof(Eth_header));

	TCP_header* tcp = (TCP_header*)((u_char*)ip + (ip->header_len << 2));

	tcp->flag = TCPFLAG_RST;

	backward_block(new_pkt, ip, tcp, 0, 0);

	int e = send_packet(dev, (uint8_t*)new_pkt, sizeof(Eth_header) + ntohs(ip->total_len));

	free(new_pkt);

	return e;
}

int backward_FIN(const char * dev, u_char* pkt, int pkt_len){

	u_char* new_pkt = (u_char*)malloc(pkt_len);
	memcpy(new_pkt, pkt, pkt_len);

	IP_header* ip = (IP_header*)(new_pkt + sizeof(Eth_header));
	TCP_header* tcp = (TCP_header*)((u_char*)ip + (ip->header_len << 2));

	tcp->flag = TCPFLAG_FIN | TCPFLAG_PSH | TCPFLAG_ACK;

	backward_block(new_pkt, ip, tcp, block_msg, sizeof(block_msg) - 1);

	int e = send_packet(dev, (uint8_t*)new_pkt, sizeof(Eth_header) + ntohs(ip->total_len));

	free(new_pkt);

	return e;
}
