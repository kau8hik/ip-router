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
#include <pcap.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include "ethrchanges.h"
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define IP_ADDR_STR_LEN 19
#define MAC_ADDR_STR_LEN 20
#define IF_STR_LEN 5

typedef struct ARP_table{
	struct in_addr other_ip, interface_ip, mask;
	char *other_ip_str, *interface_ip_str, *mask_str;
	uint8_t *other_mac_addr_in_uint;
	char if_to_send[IF_STR_LEN];
	uint8_t *interface_mac_addr;
	pcap_t *handle;
	struct ARP_table *next;
	struct rip_table *rip_link;
}ARP_table;

extern ARP_table *arp_head;

//uint8_t *parse_ether_address(char *ether_addr_str);

void parse_ARP_table();
