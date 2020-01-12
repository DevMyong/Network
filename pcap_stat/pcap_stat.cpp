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
	std::map<eth_addr, eth_endpoint> eth_map;
	std::map<ip_addr, eth_endpoint> ip_map;
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
		//eth_map.insert()
	}
	
	pcap_close(fp);
}