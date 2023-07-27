#include <windows.h>


#define PCAP_OPEN_LIVE_TO_MS_VALUE_0 -1
#define MAC_ADDRESS_LENGTH 6
#define HTTP_PORT 80
#define MAX_PCAP_BUFFER	MAX_PACKET_SIZE * 16 * 100

#define HTTP_PORT						80
#define PCAP_OPENFLAG_PROMISCUOUS		1
#define MAX_PACKET_SIZE					0x10000						
#define MTU								1500
#define MAC_ADDRESS_SIZE				6	
#define DNS_PORT						53
#define MAX_DNS_HIJACK_COUNT			4096
#define WSASTARTUP_VERSION				0x0202


#define DNS_INIT_FILENAME			"config.ini"
#define PCAP_DNS_PORT_FILTER		"ip"		//"udp dst port 53 or udp src port 53"