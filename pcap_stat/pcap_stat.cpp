#include<iostream>
#include<map>
#include"type.h"

int main(int argc, char** argv) {
	//option error
	if (argc != 2) {
		std::cout << "Usage : " << argv[0] << " pcap_file_name";
		return -1;
	}

	//pcap file error & fp 얻기
	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	if ((fp = pcap_open_offline(argv[1], errbuf)) == NULL) {
		std::cout << stderr << "\n Unable to open the file" << argv[1];
		return -1;
	}

	//packet 뜯기
	pcap_pkthdr* fpHeader;
	const UINT8* data;
	int res;
	std::map<eth_addr, eth_stat_data> eth_EP_map;
	std::map<ip_address, ip_stat_data> ip_EP_map;
	
	while ((res = pcap_next_ex(fp, &fpHeader, &data)) >= 0) {
		//시간지연될 때(나중에 쓸까봐)
		if (res == 0) {
			continue;
		}
		
		//각 헤더 정보 저장
		int offset = 0;
		const eth_header* ethHeader;
		const ip_header* ipHeader;

		ethHeader = reinterpret_cast<const eth_header*>(data);
		offset += sizeof(ethHeader);
		ipHeader = reinterpret_cast<const ip_header*>(data + offset);
		
		// Endpoint 저장
		auto eth_EP_itr = eth_EP_map.find(ethHeader->eth_addr_src);
		if (eth_EP_itr == eth_EP_map.end()) {
			eth_addr eth_address;
			eth_stat_data tx_value = { 0 };
			eth_stat_data rx_value = { 0 };

			eth_address = ethHeader->eth_addr_src;
			tx_value.tx_Bytes += fpHeader->caplen;
			tx_value.tx_Pack++;
			tx_value.bytes += fpHeader->caplen;
			tx_value.nPack++;

			eth_address = ethHeader->eth_addr_dst;
			rx_value.rx_Bytes += fpHeader->caplen;
			rx_value.rx_Pack++;
			rx_value.bytes += fpHeader->caplen;
			rx_value.nPack++;

			eth_EP_map.insert({ ethHeader->eth_addr_src, tx_value });
			eth_EP_map.insert({ ethHeader->eth_addr_dst, rx_value });
		}

		auto ip_EP_itr = ip_EP_map.find(ipHeader->saddr);
		if (ip_EP_itr == ip_EP_map.end()) {
			ip_address ip_addr;
			ip_stat_data tx_value = { 0 };
			ip_stat_data rx_value = { 0 };

			ip_addr = ipHeader->saddr;
			tx_value.tx_Bytes += fpHeader->caplen;
			tx_value.tx_Pack++;
			tx_value.bytes += fpHeader->caplen;
			tx_value.nPack++;

			ip_addr = ipHeader->daddr;
			rx_value.rx_Bytes += fpHeader->caplen;
			rx_value.rx_Pack++;
			rx_value.bytes += fpHeader->caplen;
			rx_value.nPack++;

			ip_EP_map.insert({ ipHeader->saddr, tx_value });
			ip_EP_map.insert({ ipHeader->daddr, rx_value });
		}

		// conversation 저장
		auto ip_CONV_itr = ip_CONV_map.find({ ipHeader->saddr, ipHeader->daddr },tx_value);
	}

	
	pcap_close(fp);
}