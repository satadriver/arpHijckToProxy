
#ifndef PUBLIC_H_H_H
#define PUBLIC_H_H_H

#include <windows.h>

#define MAC_ADDRESS_SIZE				6	


DWORD GetSubNet(char * szIP,char * szSubNet);
int GetNetCardInfo(DWORD * dwIP,char * lpMac,char * szNetIP,DWORD * dwGateWayIP,char * lpGateWayMac);
DWORD GetLocalIpAddress();
DWORD WriteLogFile(char * pFileName,char * pData,DWORD dwDataSize);
int RecordInFile(char * szFileName,unsigned char * strBuffer,int iCounter);
#endif