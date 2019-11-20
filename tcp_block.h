#pragma once

#include <stdint.h>

#define calculate_IP_hlen(iphlen, tcphlen) (((int)(iphlen) << 2) + ((int)(tcphlen) << 2))

using namespace std;

int forward_RST(const char * dev, u_char* pkt, IP_header* ip, TCP_header* tcp);
int forward_FIN(const char * dev, u_char* pkt, IP_header* ip, TCP_header* tcp);
int backward_RST(const char * dev, u_char* pkt, IP_header* ip, TCP_header* tcp);
int backward_FIN(const char * dev, u_char* pkt, IP_header* ip, TCP_header* tcp);
