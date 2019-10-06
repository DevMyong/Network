#ifndef MYPCAP_H
#define MYPCAP_H

#endif // MYPCAP_H

#include <pcap.h>
#include <stdio.h>
#include <string>
#include <arpa/inet.h>

using namespace std;
#define SRC 0
#define DST 1

void usage();
void printMac(const u_char *pckt, bool dir);
bool chkEtherType(const u_char *pckt);
void printIP(const u_char *pckt, bool dir);
bool chkProtocol(const u_char *pckt);
void printPort(const u_char *pckt, bool dir);
void printTcpSegment(const u_char *pckt, pcap_pkthdr *hd);
