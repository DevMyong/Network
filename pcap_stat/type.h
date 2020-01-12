#pragma once
#include<pcap.h>

typedef UINT32 ip_addr;
typedef struct ip_header {
	UINT8	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	UINT8	tos;			// Type of service 
	UINT16	tlen;			// Total length 
	UINT16	identification; // Identification
	UINT16	flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	UINT8	ttl;			// Time to live
	UINT8	proto;			// Protocol
	UINT16	crc;			// Header checksum
	UINT32	saddr;		// Source address
	UINT32	daddr;		// Destination address
	UINT32	op_pad;			// Option + Padding
}ip_header;

typedef struct eth_address {
	UINT8	dth_addr[6];
}eth_addr;

typedef struct eth_header {
	eth_addr	eth_addr_dst;
	eth_addr	eth_addr_src;
	UINT16	eth_type;
}eth_header;

typedef struct eth_endpoint {
	eth_addr address;
	UINT32	nPack;
	UINT32	bytes;
	UINT32	txPack;
	UINT32	txBytes;
	UINT32	rxPack;
	UINT32	rxBytes;
};
typedef struct ip_endpoint {
	UINT32 address;
	UINT32	nPack;
	UINT32	bytes;
	UINT32	txPack;
	UINT32	txBytes;
	UINT32	rxPack;
	UINT32	rxBytes;
};