#include <pcap.h>
#include <stdio.h>
#include <string>
#include <arpa/inet.h>

using namespace std;
#define SRC 0
#define DST 1

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

    nexthdr = ((((pckt[14] & 0xF0) >> 4) * ((pckt[14] & 0x0F))) +14)/2; //14 is ether length

    if(dir==SRC)printf("SPORT : %d\n",ntohs(p[nexthdr]));
    else if(dir==DST) printf("DPORT : %d\n",ntohs(p[nexthdr+1]));
}
void printTcpSegment(const u_char *pckt){
    u_char nexthdr=0;
    u_char len=0;
    nexthdr = (((pckt[14] & 0xF0) >> 4) * ((pckt[14] & 0x0F))) +14 + 12; //iphdr + ether hdr is ether length
    len=(((pckt[nexthdr] & 0xF0) >> 4) * 4); //TCP length is (4 * len)
    printf("TCP Len : %d\n", len);
    printf("TCP Data :");
    for(int i=0;i<10;i++){
        printf(" %02x", pckt[nexthdr+len+i]);
        if(pckt[nexthdr+len+i-1]==0x0d && pckt[nexthdr+len+i]==0x0a)
            if(pckt[nexthdr+len+i-3]==0x0d && pckt[nexthdr+len+i-2]==0x0a) break;
    }
    printf("\n\n");
}
int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //typing by me
    printMac(packet, SRC);
    printMac(packet, DST);

    if(chkEtherType(packet)){
        printIP(packet, SRC);
        printIP(packet, DST);
        if(chkProtocol(packet)){
            printPort(packet, SRC);
            printPort(packet, DST);
            printTcpSegment(packet);
        }
        else continue;
    }
    else continue;
  }
  pcap_close(handle);
  return 0;
}
