#pragma once

#include <stdint.h>

void calculate_IP_checksum(IP_header* ip);
void calculate_TCP_checksum(const IP_header* ip, TCP_header* tcp, int tcp_length);
