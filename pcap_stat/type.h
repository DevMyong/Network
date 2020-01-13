#pragma once
#include<pcap.h>

typedef UINT32 ip_address;
typedef struct ip_header {
	UINT8	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	UINT8	tos;			// Type of service 
	UINT16	tlen;			// Total length 
	UINT16	identification; // Identification
	UINT16	flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	UINT8	ttl;			// Time to live
	UINT8	proto;			// Protocol
	UINT16	crc;			// Header checksum
	UINT32	saddr;			// Source address
	UINT32	daddr;			// Destination address
	UINT32	op_pad;			// Option + Padding
}ip_header;

typedef struct eth_address {
	UINT8	eth_addr[6];

	bool operator<(const eth_address& other) const{
		for (int i = 0; i < 6; i++) {
			if (eth_addr[i] < other.eth_addr[i]) return true;
			else if (eth_addr[i] > other.eth_addr[i]) return false;
			else continue;
		}
		return false;
	}
	
}eth_addr;

typedef struct eth_header {
	eth_addr	eth_addr_dst;
	eth_addr	eth_addr_src;
	UINT16	eth_type;
}eth_header;

typedef struct eth_stat_data {
	UINT32	nPack;
	UINT32	bytes;
	UINT32	tx_Pack;
	UINT32	tx_Bytes;
	UINT32	rx_Pack;
	UINT32	rx_Bytes;
};
typedef struct ip_stat_data {
	UINT32	nPack;
	UINT32	bytes;
	UINT32	tx_Pack;
	UINT32	tx_Bytes;
	UINT32	rx_Pack;
	UINT32	rx_Bytes;
};
typedef struct conversation_eth {
	eth_addr saddr;
	eth_addr daddr;
}conv_eth;
typedef struct conversation_ip {
	UINT32 saddr;
	UINT32 daddr;
}conv_ip;
