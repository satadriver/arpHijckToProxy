
#include <windows.h>
#include <IPHlpApi.h>
#pragma comment(lib,"iphlpapi.lib")
#include <stdio.h>
#include "MainProc.h"








DWORD GetLocalIpAddress()
{
	char local[MAX_PATH] = {0};
	int iRet = gethostname(local, sizeof(local));
	if (iRet )
	{
		return FALSE;
	}
	hostent* ph = gethostbyname(local);
	if (ph == NULL)
	{
		return FALSE;
	}

	in_addr addr = {0};
	memcpy(&addr, ph->h_addr_list[0], sizeof(in_addr)); 
	if (addr.S_un.S_addr == 0)
	{
		return FALSE;
	}
	return addr.S_un.S_addr;
}




DWORD GetSubNet(char * szIP,char * szSubNet){

	char * pHdr = szIP;
	char * pEnd = szIP;

	pHdr = strstr(pHdr,".");
	if (pHdr == FALSE)
	{
		return FALSE;
	}
	pHdr += 1;

	pHdr = strstr(pHdr,".");
	if (pHdr == FALSE)
	{
		return FALSE;
	}
	pHdr += 1;

	pEnd = strstr(pHdr,".");
	if (pEnd == FALSE)
	{
		return FALSE;
	}

	memmove(szSubNet,pHdr,pEnd - pHdr);
	return TRUE;
}



int GetNetCardInfo(DWORD * dwIP,char * lpMac,char * szNetIP,DWORD * dwGateWayIP,char * lpGateWayMac)
{
	char strGateWayIP[MAX_PATH] = {0};
	char strIP[MAX_PATH] = {0};

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO); 
	PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)GlobalAlloc(GPTR,sizeof(IP_ADAPTER_INFO)); 
	if(pAdapterInfo == NULL) 
	{
		return FALSE; 
	}
	// Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable 
	if(GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)  
	{ 
		GlobalFree((char*)pAdapterInfo); 
		pAdapterInfo = (IP_ADAPTER_INFO *)GlobalAlloc(GPTR,ulOutBufLen); 
		if (pAdapterInfo == NULL)
		{
			return FALSE; 
		}
	} 

	//no netcard will cause this function return error
	if(GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) 
	{ 
		for(PIP_ADAPTER_INFO pAdapter = pAdapterInfo; pAdapter != NULL; pAdapter = pAdapter->Next) 
		{ 
			if(pAdapter->Type != MIB_IF_TYPE_ETHERNET && pAdapter->Type !=  IF_TYPE_IEEE80211){ 
				continue; 
			}
			if(pAdapter->AddressLength != MAC_ADDRESS_LENGTH) {
				continue; 
			}
			if (lstrlenA(pAdapter->IpAddressList.IpAddress.String) < 8 || lstrlenA(pAdapter->GatewayList.IpAddress.String) < 8)
			{
				continue;
			}

			if (memcmp(pAdapter->IpAddressList.IpAddress.String,"0.0.0.0",7) != 0 && memcmp(pAdapter->GatewayList.IpAddress.String,"0.0.0.0",0) != 7)
			{
				memmove(lpMac,pAdapter->Address,MAC_ADDRESS_LENGTH);

				lstrcpyA(strGateWayIP,pAdapter->GatewayList.IpAddress.String);

				lstrcpyA(strIP,pAdapter->IpAddressList.IpAddress.String);

				char szSubNetGateWayIP[4] = {0};
				char szSubNet[4] = {0};
				GetSubNet(strGateWayIP,szSubNetGateWayIP);
				GetSubNet(strIP,szSubNet);
				if (lstrcmpA(szSubNet,szSubNetGateWayIP) == 0)
				{
					break;
				}
				else{
					IP_ADDR_STRING * lpNext = pAdapter->IpAddressList.Next;
					while (lpNext)
					{
						lstrcpyA(strIP,lpNext->IpAddress.String);
						GetSubNet(strIP,szSubNet);
						if (lstrcmpA(szSubNet,szSubNetGateWayIP) == 0)
						{
							break;
						}
						else{
							lpNext = lpNext->Next;
						}
					}
				}
			}
		} 
	}
	else
	{
		GlobalFree((char*)pAdapterInfo); 
		return FALSE;
	}
	GlobalFree((char*)pAdapterInfo); 

	*dwIP = inet_addr(strIP);
	*dwGateWayIP = inet_addr(strGateWayIP);

	sockaddr_in stServSockAddr = {0};
	char szIp138Buf[4096];
	char * _szIp138Url	= \
		"GET /ic.asp HTTP/1.1\r\n"\
		"Referer: %s\r\n"\
		"Accept-Language: zh-cn\r\n"\
		"Accept-Encoding: gzip, deflate\r\n"\
		"Host: %s\r\n"\
		"Connection: Keep-Alive\r\n\r\n";
	char szIp138Host[]		= {'1','2','1','2','.','i','p','1','3','8','.','c','o','m',0};
	char szIp138Referer[]	= {'h','t','t','p',':','/','/','w','w','w','.','i','p','1','3','8','.','c','o','m','/',0};
	//no netcard will cause this function return 0
	hostent * pHostent =  gethostbyname(szIp138Host);		//get ip from host name
	if (pHostent == 0)
	{
		int iRet = GetLastError();	//10093= wsastartup
		return FALSE;
	}
	ULONG  pPIp = *(DWORD*)((CHAR*)pHostent + sizeof(hostent) - sizeof(DWORD_PTR));
	ULONG  pIp = *(ULONG*)pPIp;
	stServSockAddr.sin_addr.S_un.S_addr = *(DWORD*)pIp;
	stServSockAddr.sin_port = ntohs(HTTP_PORT);
	stServSockAddr.sin_family = AF_INET;

	SOCKET hSock = socket(AF_INET,SOCK_STREAM,0);
	if(hSock == INVALID_SOCKET)
	{
		return FALSE;
	}

	int iRet = connect(hSock,(sockaddr*)&stServSockAddr,sizeof(sockaddr_in));
	if(iRet == INVALID_SOCKET)
	{
		closesocket(hSock);
		return FALSE;
	}

	iRet = wsprintfA(szIp138Buf,_szIp138Url,szIp138Referer,szIp138Host);
	iRet = send(hSock,szIp138Buf,iRet,0);
	if(iRet <= 0)
	{
		closesocket(hSock);
		return FALSE;
	}

	iRet = recv(hSock,szIp138Buf,4096,0);
	if(iRet <= 0)
	{
		closesocket(hSock);
		return FALSE;
	}
	*(UINT*)(szIp138Buf + iRet) = 0;
	closesocket(hSock);

	char szFlagHdr[] = {'<','c','e','n','t','e','r','>',0};
	char szFlagEnd[] = {'<','/','c','e','n','t','e','r','>',0};
	char * pInetIp = strstr(szIp138Buf,szFlagHdr);
	if(pInetIp)
	{
		pInetIp += lstrlenA(szFlagHdr);
		char * pInetIpEnd = strstr(pInetIp,szFlagEnd);
		if(pInetIpEnd)
		{
			memmove(szNetIP,pInetIp,pInetIpEnd - pInetIp);
		}
	}

	return FALSE;
}




DWORD WriteLogFile(char * pFileName,char * pData,DWORD dwDataSize)
{
	HANDLE hFile = CreateFileA(pFileName,GENERIC_READ | GENERIC_WRITE,0,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD dwCnt = SetFilePointer(hFile,0,0,FILE_END);
	if (dwCnt == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	int iRet = WriteFile(hFile,pData,dwDataSize,&dwCnt,0);
	CloseHandle(hFile);
	if (iRet == 0 || dwCnt != dwDataSize)
	{
		return FALSE;
	}

	return TRUE;
}








int RecordInFile(char * szFileName,unsigned char * strBuffer,int iCounter)
{
	int iRet = 0;
	FILE * fpFile = 0;
	iRet = fopen_s(&fpFile,szFileName,"a");
	if (fpFile )
	{
		unsigned long ulFileSize = fseek(fpFile,0,SEEK_END);
		iRet = fwrite(strBuffer,1,iCounter,fpFile);
		if (iRet != iCounter)
		{
			fclose(fpFile);
			printf("写文件错误\n");
			return FALSE;
		}
		fclose(fpFile);
		return TRUE;
	}
	else if (fpFile == 0)
	{
		iRet = fopen_s(&fpFile,szFileName,"w");
		if (fpFile)
		{
			unsigned long ulFileSize = fseek(fpFile,0,SEEK_END);
			fwrite(strBuffer,1,iCounter,fpFile);	
			if (iRet != iCounter)
			{
				printf("写文件错误\n");
				fclose(fpFile);
				return FALSE;
			}
			fclose(fpFile);
			return TRUE;
		}
		else
		{
			printf("打开文件错误\n");
			return FALSE;
		}
	}
	return FALSE;
}