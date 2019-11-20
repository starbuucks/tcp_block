#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "packet.h"
#include "packet_util.h"
#include "tcp_block.h"

using namespace std;

char block_msg[] = "HTTP/1.0 302 Redirect\x0d\x0aLocation: http://warning.or.kr/i1.html\x0d\x0a\x0d\x0a";

void forward_block(u_char* pkt, IP_header* ip, TCP_header* tcp, char* tcp_data, int data_len){
	int tcp_data_len = ip->total_len - tcp->hlen << 2;

	ip->total_len = calculate_IP_hlen(ip->header_len, TCPHLEN_MIN);

	calculate_IP_checksum(ip);

	tcp->seq_num = tcp->seq_num + tcp_data_len;
	
	tcp->hlen = TCPHLEN_MIN;



	calculate_TCP_checksum(ip, tcp, tcp->hlen << 2 + data_len);
}

void backward_block(u_char* pkt, IP_header* ip, TCP_header* tcp){
	MAC mac_tmp;
	mac_tmp = ((Eth_header*)pkt)->dst_mac;
	((Eth_header*)pkt)->dst_mac = ((Eth_header*)pkt)->src_mac;
	((Eth_header*)pkt)->src_mac = mac_tmp;

	uint32_t newseq = htonl(ntohl(tcp->seq_num) + ntohs(ip->total_len) - calculate_IP_hlen(ip->header_len, tcp->hlen));
	uint32_t tmp;
	tmp = ip->src_ip;
	ip->src_ip = ip->dst_ip;
	ip->dst_ip = tmp;

	ip->total_len = htons(calculate_IP_hlen(ip->header_len, TCPHLEN_MIN));

	calculate_IP_checksum(ip);

	tmp = tcp->src_port;
	tcp->src_port = tcp->dst_port;
	tcp->dst_port = tmp;

	tcp->seq_num = tcp->ack_num;
	tcp->ack_num = newseq;

	tcp->hlen = TCPHLEN_MIN;
	tcp->window = 0;

	calculate_TCP_checksum(ip, tcp, tcp->hlen << 2);
}

int forward_RST(const char * dev, u_char* pkt, IP_header* ip, TCP_header* tcp){
	tcp->flag = TCPFLAG_RST;



}

int forward_FIN(const char * dev, u_char* pkt, IP_header* ip, TCP_header* tcp){
	tcp->flag = TCPFLAG_FIN | TCPFLAG_PSH | TCPFLAG_ACK;

}

int backward_RST(const char * dev, u_char* pkt, IP_header* ip, TCP_header* tcp){
	tcp->flag = TCPFLAG_RST;

	backward_block(pkt, ip, tcp);

	return send_packet(dev, (uint8_t*)pkt, sizeof(Eth_header) + ntohs(ip->total_len));
}

int backward_FIN(const char * dev, u_char* pkt, IP_header* ip, TCP_header* tcp){
	tcp->flag = TCPFLAG_FIN | TCPFLAG_PSH | TCPFLAG_ACK;

	backward_block(pkt, ip, tcp);

	memcpy(pkt + sizeof(Eth_header) + ntohs(ip->total_len), block_msg, sizeof(block_msg));

	ip->total_len = htons(ntohs(ip->total_len) + sizeof(block_msg));

	return send_packet(dev, (uint8_t*)pkt, sizeof(Eth_header) + ntohs(ip->total_len));
}
