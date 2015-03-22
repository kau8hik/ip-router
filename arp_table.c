#include "arp_table.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

ARP_table *arp_head = NULL;

uint8_t * getMacAddr(char *interface_name)
{
	unsigned char MAC_str[18];
#define HWADDR_len 6
	int s,i;
	struct ifreq ifr;
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if(s == -1){
		printf("Unable to create socket %d",errno);
		exit(1);
	}
	strcpy(ifr.ifr_name, interface_name);
	ioctl(s, SIOCGIFHWADDR, &ifr);
	for (i=0; i<HWADDR_len; i++){
		sprintf(&MAC_str[i*3],"%02X",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
		if(i!=0) MAC_str[i*3-1] = ':';
	}
	MAC_str[17]='\0';
	close(s);
	uint8_t *ret = parse_ether_address(MAC_str);

	return ret;
}

void getAllInterfaceNames(){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	int status = pcap_findalldevs(&alldevs, errbuf);
	if(status != 0) {
		printf("%s\n", errbuf);
		exit (1);
	}
	pcap_if_t *d;
	for(d=alldevs; d!=NULL; d=d->next) {
		pcap_addr_t *a;
		int flag = 0;
		for(a=d->addresses; a!=NULL; a=a->next) {
			if(a->addr->sa_family == AF_INET && d->flags != PCAP_IF_LOOPBACK){
				char *ip_ad = inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr);
				if(!strncmp(inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr),"192.168",7)){
					printf("ignoring 192.168\n");
				}
				else{
					ARP_table *tmp = arp_head;
					while(tmp){
						if(!strcmp(tmp->if_to_send, d->name)){
							tmp->interface_ip = (((struct sockaddr_in *)a->addr)->sin_addr);

							char *tmp_interface_ip = inet_ntoa((((struct sockaddr_in *)a->addr)->sin_addr));
							tmp->interface_ip_str = (char*)calloc(1,sizeof(strlen(tmp_interface_ip)));
							strncpy(tmp->interface_ip_str, tmp_interface_ip, strlen(tmp_interface_ip));

							tmp->mask = (((struct sockaddr_in *)a->netmask)->sin_addr);

							char *tmp_mask = inet_ntoa((((struct sockaddr_in *)a->netmask)->sin_addr));
							tmp->mask_str = (char *)calloc(1,sizeof(strlen(tmp_mask)));
							strncpy(tmp->mask_str, tmp_mask, strlen(tmp_mask));
							
					//strcpy(node->device_addr, inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
					//strcpy(node->device_mask, inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr));
							tmp->interface_mac_addr = getMacAddr(tmp->if_to_send);						
							flag = 1;
							break;

						}
						tmp = tmp->next;
					}
				}
				if(flag) break;
			}
		}
	}
	ARP_table *tmp = arp_head;
	while(tmp){
		printf("Interfaces---------------> %s %s\n",tmp->if_to_send, inet_ntoa(tmp->other_ip));
		tmp = tmp->next;
	}
}

void parse_ARP_table(){
	char ip_addr[IP_ADDR_STR_LEN];
	char mac_addr[MAC_ADDR_STR_LEN];
	char device[IF_STR_LEN];
	char hw_type[12];
	char flag[12];
	char mask[IP_ADDR_STR_LEN];

	ARP_table *head;
	ARP_table *tail;
	FILE *fp  = fopen ("arp", "r");
	//FILE *fp  = fopen ("/proc/net/arp", "r");
	if(fp == NULL)
		exit(1);

	char buf[80];
	fgets(buf, 80, fp);
	while (fscanf(fp, "%s\t%s\t%s\t%s\t%s\t%s", &ip_addr, &hw_type, &flag, &mac_addr, &mask, &device)!= EOF)
	{
		if(!strncmp(ip_addr,"192.168",7) || !strncmp(ip_addr,"127.0",5)) continue;
		ARP_table *node = (ARP_table *)malloc(sizeof(ARP_table));
		struct in_addr to_net;
		printf("%d --------\n",inet_aton(ip_addr, (struct in_addr *)&to_net)); 
		if(inet_aton(ip_addr, (struct in_addr *)&to_net) == 0)
			printf("Error during inet_aton %d", errno);
		node->other_ip.s_addr = to_net.s_addr;
		
		char *tmp_other_ip = ip_addr;
		node->other_ip_str = (char *)calloc(1,sizeof(strlen(tmp_other_ip)));
		strncpy(node->other_ip_str, tmp_other_ip, strlen(tmp_other_ip));

		node->other_mac_addr_in_uint = parse_ether_address(mac_addr);
		memset(node->if_to_send,0,sizeof(node->if_to_send));
		memcpy(node->if_to_send,device,strlen(device));
		node->next = NULL;
		node->rip_link = NULL;
		if(arp_head == NULL) {
			arp_head = node;
			tail = node;
		}
		else{
			tail->next = node;
			tail = node;
		}
	}
	getAllInterfaceNames();
	fclose(fp);

	//ARP_table *tmp;
	//tmp = arp_head;
	//while(tmp){
	//	printf("%s \t %s \t %s\n",tmp->ip_addr, tmp->mac_addr, tmp->if_to_send);
	//	tmp = tmp->next;
	//}
}
