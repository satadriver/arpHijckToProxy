#ifndef WINPCAPDNSHIJACK_H_H_H
#define WINPCAPDNSHIJACK_H_H_H



#include "..\\include\\pcap.h"
#include "..\\include\\pcap\\pcap.h"
#include <map>
#include "MainProc.h"


typedef struct{
	pcap_t * pcapMain;
	DWORD dwLocalIP;
	DWORD dwGateWayIP;
	DWORD dwHijackIP;
	char lpLocalMac[MAC_ADDRESS_SIZE];
	char lpGateWayMac[MAC_ADDRESS_SIZE];
	char lpHijackMac[MAC_ADDRESS_SIZE];
	char * lpPcapErrorBuf;
}ARP_CHEAT_PARAM,*LPARP_CHEAT_PARAM;


WORD CalcChecksum(WORD *buffer,int size);
USHORT GetUdpCheckSum(LPUDPHEADER pUdp,DWORD dwSrcIP,DWORD dwDstIP);
int __stdcall SnifferHijack(LPARP_CHEAT_PARAM stParam);
int __stdcall ThreadArpCheat(LPARP_CHEAT_PARAM lpParam);


#endif