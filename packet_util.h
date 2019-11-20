#pragma once

#include <stdint.h>

int send_packet(const char * dev, uint8_t* pkt, int packet_len);
void calculate_IP_checksum(IP_header* ip);
void calculate_TCP_checksum(const IP_header* ip, TCP_header* tcp, int tcp_length);
