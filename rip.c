#include "rip.h"
#include<signal.h>
#include<unistd.h>

void print_routing_table(){
	ARP_table *tmp = arp_head;
	while(tmp){
		rip_table *tmp_rip = tmp->rip_link;
		while(tmp_rip){
			char *mask =(char *)calloc(sizeof(char),1);
			memcpy(mask, inet_ntoa(tmp_rip->mask), strlen(inet_ntoa(tmp_rip->mask)));	
			printf("%s, %s, %s %d \n", inet_ntoa(tmp_rip->dst_ip), tmp->other_ip_str, mask, tmp_rip->metric);
			tmp_rip = tmp_rip->next;
		}
		tmp = tmp->next;
	}
}

void *send_rip_update(){
	ARP_table *tmp_arp_head = arp_head;
	while(tmp_arp_head){
		rip_table *tmp_rip_head = tmp_arp_head->rip_link;
		while(tmp_rip_head){
			printf("On interface %s\n", tmp_arp_head->if_to_send);
			tmp_rip_head->cnt++;
			tmp_rip_head = tmp_rip_head->next;
			//struct in_addr tmpaddr = tmp_rip_head->mask;

			//printf("The dst ip, mask, metric %s\n",inet_ntoa(tmpaddr));
		}
		tmp_arp_head = tmp_arp_head->next;
	}
	//send_rip();
	print_routing_table();
 	signal(SIGALRM, send_rip_update);
	alarm(1);
//sleep(30);
}

ARP_table * get_ARP_table_row(struct in_addr dst_ip){
	ARP_table *tmp_arp_head = arp_head;
	int rip_metric = 32;
	ARP_table *ptr_to_return = NULL;
	while(tmp_arp_head){
		rip_table *tmp_rip_head = tmp_arp_head->rip_link;
		while(tmp_rip_head){
			if(tmp_rip_head->dst_ip.s_addr == (dst_ip.s_addr&tmp_rip_head->mask.s_addr)){ //&& (ntohl(tmp_rip_head->metric)<=rip_metric) && ntohl(tmp_rip_head->metric)<=6){
				ptr_to_return = tmp_arp_head;
			}
			tmp_rip_head = tmp_rip_head->next;
		}
		tmp_arp_head = tmp_arp_head->next;
	}
	return ptr_to_return;
}

void parse_rip(u_char *Buffer)
{
		struct ether_header *eptr = (struct ether_header *)Buffer; 
	unsigned short iphdrlen;
    	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    	iphdrlen = iph->ihl*4; 
    	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	struct rip *ripE = (struct rip*) (Buffer + iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr));
	struct netinfo *ripH = (struct netinfo*) (Buffer + iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr) + 4);
	u_int32_t ipdst=(ripH->n_dst);
	struct in_addr addr, mask;
	addr.s_addr =	(ipdst);
	mask.s_addr = ripH->n_mask;
	char *ipaddr = inet_ntoa(addr);
	printf("IP address %s\n",ipaddr);
	
	int ripHLEN =12 ;
	ARP_table *tmp = arp_head;
	rip_table *rip_head;
	while(tmp){
		if(tmp->other_ip.s_addr == iph->saddr){
			rip_head = tmp->rip_link;
			break;
		}
		tmp = tmp->next;
	}
	while(ripHLEN!=ntohs(udph->len))
	{
		int found_rip_entry = 0;
		if(rip_head == NULL){
			rip_table *node = (rip_table *)malloc(sizeof(rip_table));
			node->dst_ip.s_addr = ripH->n_dst;
			node->mask.s_addr = ripH->n_mask;
			node->metric = ripH->n_metric;
			node->cnt = 0;
			node->next = NULL;
			tmp->rip_link = node;	
			break;
		}
		rip_table *tmp_rip = rip_head;
		while(tmp_rip){
			if(tmp_rip->dst_ip.s_addr == ripH->n_dst){
				tmp_rip->mask.s_addr = ripH->n_mask;
				tmp_rip->metric = ripH->n_metric;
				tmp_rip->cnt = 0;
				found_rip_entry = 1;
			}
			tmp_rip = tmp_rip->next;
		}
		tmp_rip = rip_head;
		if(!found_rip_entry){
			while(tmp_rip->next){
				tmp_rip = tmp_rip->next;
			}
			rip_table *node = (rip_table *)malloc(sizeof(rip_table));
			tmp_rip->next = node;
			node->dst_ip.s_addr = ripH->n_dst;
			node->mask.s_addr = ripH->n_mask;
			node->metric = ripH->n_metric;
			node->cnt = 0;
			node->next = NULL;
		}

		fprintf(stdout,"   |-rip next_dest      : %d\n" , ripH->n_dst);
		fprintf(stdout,"   |-rip mask : %d\n" , ripH->n_mask);
		fprintf(stdout,"   |-rip nhop      : %d\n" ,ripH->n_nhop);
		fprintf(stdout,"   |-rip metric : %d\n" , ripH->n_metric);
		ripHLEN+=20;
		ripH+=1;
	}
}	

