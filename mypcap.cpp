#include"mypcap.h"

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
void printMac(const u_char *pckt, bool dir){
    if(dir==SRC) printf("SMAC : %02x:%02x:%02x:%02x:%02x:%02x\n",pckt[0],pckt[1],pckt[2],pckt[3],pckt[4],pckt[5]);
    else if(dir==DST) printf("DMAC : %02x:%02x:%02x:%02x:%02x:%02x\n",pckt[6],pckt[7],pckt[8],pckt[9],pckt[10],pckt[11]);
}
bool chkEtherType(const u_char *pckt){
    u_char *pp = const_cast<u_char *>(pckt);
    u_int16_t *p = reinterpret_cast<u_int16_t*>(pp);

    if(ntohs(p[6])==0x800) {
        printf("Type : IPv4\n\n");
        return true;
    }
    else {
        printf("Type : !(IPv4)\n\n");
        return false;
    }
}
void printIP(const u_char *pckt, bool dir){
    if(dir==SRC) printf("SIP : %d.%d.%d.%d\n", pckt[26],pckt[27],pckt[28],pckt[29]);
    else if(dir==DST) printf("DIP : %d.%d.%d.%d\n", pckt[30],pckt[31],pckt[32],pckt[33]);
}
bool chkProtocol(const u_char *pckt){
    if(pckt[23]==6){
        printf("Type : TCP\n\n");
        return true;
    }
    else {
        printf("Type : !(TCP)\n\n");
        return false;
    }
}
void printPort(const u_char *pckt, bool dir){
    u_char *pp = const_cast<u_char *>(pckt);
    u_int16_t *p = reinterpret_cast<u_int16_t*>(pp);
    u_char nexthdr=0;

    nexthdr = ((((pckt[14] & 0xF0) >> 4) * (pckt[14] & 0x0F)) +14)/2; //+14 is ether length
    // duplication's meaning is in changing a data type. because nexthdr is idx and p's data type is short(2bytes).
    if(dir==SRC)printf("SPORT : %d\n",ntohs(p[nexthdr]));
    else if(dir==DST) printf("DPORT : %d\n",ntohs(p[nexthdr+1]));
}
void printTcpSegment(const u_char *pckt, pcap_pkthdr *hd){
    int etherLen = 0, ipLen = 0, tcpLen = 0, tcpLen_idx=0, tcpData_idx;

    etherLen = 14;
    ipLen = (((pckt[14] & 0xF0) >> 4) * (pckt[14] & 0x0F));
    tcpLen_idx = etherLen + ipLen + 12;
    //ether + iphdr +  tcphdr's len idx is ether length
    tcpLen = ((pckt[tcpLen_idx] & 0xF0) >> 4) * 4;
    tcpData_idx = etherLen + ipLen + tcpLen;

    //prevent null printing
    for(int i=0;i<10;i++){
        if(hd->caplen <= tcpData_idx) break;
        printf("(idx:%d) %02x\n",(tcpData_idx+i), pckt[tcpData_idx+i]);
        if(pckt[tcpData_idx+i-1]==0x0d && pckt[tcpData_idx+i]==0x0a)
            if(pckt[tcpData_idx+i-3]==0x0d && pckt[tcpData_idx+i-2]==0x0a) break;
    }
    printf("\n\n");
}
