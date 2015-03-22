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
#define IP_ADDR_STR_LEN 19
#define MAC_ADDR_STR_LEN 20
#define IF_STR_LEN 5
/*typedef struct IP_table{
	char *dest_addr;
	char *gateway_addr;
	char *iface;
	struct IP_table *next;
}IP_table;

extern IP_table *head_ip_table;

IP_table *get_IP_table_row(char *ip);
*/

void populate_IP_table();
#include "rip.h"
#include "route_table.h"

//IP_table *head_ip_table = NULL;
/*IP_table *get_IP_table_row(char *ip){
	printf("In ip table dst ip passed %s",ip);
	IP_table *tmp;
	tmp = head_ip_table;
	while(tmp){
		if(!strcmp(ip, tmp->dest_addr)){
			printf("Returning iface %s", tmp->iface);
			return tmp;
		}
		tmp = tmp->next;
	}
	printf("Returning null\n");
	return NULL;
}*/

void populate_IP_table(){
	FILE *fp  = fopen ("iptable", "r");
	if(fp == NULL)
		exit(1);

	char buf[80];
	char ip1[IP_ADDR_STR_LEN];
	char gtw1[IP_ADDR_STR_LEN];
	char mask[IP_ADDR_STR_LEN];
	char if1[IF_STR_LEN];
	int metric;
	while (fscanf(fp, "%s\t%s\t%s\t%d", &ip1, &if1, &mask, &metric)!= EOF){
		//printf("inside polulate %s %s %s\n", ip1, gtw1, if1);
		rip_table *node;
		//IP_table *node;
		//node = (IP_table *)malloc(sizeof(IP_table));
		node = (rip_table *)malloc(sizeof(rip_table));
		struct in_addr ip;
		inet_aton(ip1, &ip);
		node->dst_ip = ip;
		inet_aton(mask, &ip);
		node->mask = ip;
		node->metric = metric;
		node->cnt = 0;
		node->next = NULL;
		ARP_table *tmp_arp_head = arp_head;
		while(tmp_arp_head){
			if(!strcmp(tmp_arp_head->if_to_send,if1)){
				struct rip_table *rip_head = tmp_arp_head->rip_link;
				if(rip_head == NULL)
					tmp_arp_head->rip_link = node;	
				else{
					while(rip_head->next!= NULL){
						rip_head = rip_head->next;
					}
					rip_head->next = node;
				}	
			}
			tmp_arp_head = tmp_arp_head->next;
		}
		//node->dest_addr = (char *)malloc(sizeof(char)*IP_ADDR_STR_LEN);
		//node->gateway_addr = (char *)malloc(sizeof(char)*IP_ADDR_STR_LEN);
		//node->iface = (char *)malloc(sizeof(char)*IF_STR_LEN);
		//strcpy(node->dest_addr, ip1);
		//strcpy(node->gateway_addr, gtw1);
		//strcpy(node->iface, if1);
		//node->next = NULL;
		/*if(head_ip_table == NULL){
			head_ip_table = node;
			tail = node;
		}
		else{
			tail->next = node;
			tail = node;
		}*/
	}
	fclose(fp);
	//IP_table *tmp = head_ip_table;
	//while(tmp){
	//	printf("inside polulate %s %s %s\n", tmp->dest_addr, tmp->gateway_addr, tmp->iface);
	//	tmp = tmp->next;
	//}
}
