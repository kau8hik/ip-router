#include <pcap.h>
#include <stdio.h>
#include <signal.h>     /* for signal */
#include <sys/time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#define IP_ADDR_STR_LEN 19
#define MAC_ADDR_STR_LEN 20
#define IF_STR_LEN 5
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define ETHER_TYPE_ARP (0x0806)
#define SIZE_ETHERNET 14
#define ETHERNET_HEADER_LEN 14
#define IP_PROTO_ICMP 1 


typedef struct interfaces{
	char *device_name;
	char *device_addr;
	char *device_mask;
	char *mac_addr; 
	uint8_t *mac_addr_in_uint;
	pcap_t *handle;
	struct interfaces *next;
}interfaces;

extern interfaces *head_iface;

#define IP_ADDR_STR_LEN 19
#define MAC_ADDR_STR_LEN 20  

u_char *modify_packet(u_char *pkt_ptr,int pkt_type, int len,uint8_t* ether_src, uint8_t* ether_dst);


char * get_mac_addr(char *iface);

void sniff_open(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);

void *sniff_and_send(void *arg);


