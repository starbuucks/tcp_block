#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include "packet.h"
#include "packet_util.h"

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

void calculate_TCP_checksum(TCP_header* tcp){
	
}
