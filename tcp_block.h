#pragma once

#include <stdint.h>

using namespace std;

int forward_RST(const char * dev, u_char* pkt, int pkt_len);
int forward_FIN(const char * dev, u_char* pkt, int pkt_len);
int backward_RST(const char * dev, u_char* pkt, int pkt_len);
int backward_FIN(const char * dev, u_char* pkt, int pkt_len);
