#include "rip.h"

# define T 5

/*int  main(void){
    signal(SIGALRM, process_rip_packet);   
    alarm(1);                         
    while (1);  
}*/

void create_socket_send(char *payload, int payload_len, struct in_addr ip_tosend){
	int sockfd, portno =520, n;
    struct sockaddr_in groupSock,sendSock;
	
	memset((char *) &sendSock, 0, sizeof(sendSock));
	sendSock.sin_family = AF_INET;
	sendSock.sin_addr.s_addr= htonl(INADDR_ANY);
	sendSock.sin_port=htons(520); //source port for outgoing packets
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	
	memset((char *) &groupSock, 0, sizeof(groupSock));
	groupSock.sin_family = AF_INET;
	groupSock.sin_addr.s_addr = inet_addr("224.0.0.9");
	groupSock.sin_port = htons(520);
	
	bind(sockfd,(struct sockaddr *)&sendSock,sizeof(sendSock));
	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, (char *)&ip_tosend, sizeof(ip_tosend)) < 0){
	  perror("Setting local interface error");
	  exit(1);
	}
	else{
		n = sendto(sockfd,payload, payload_len, 0, (struct sockaddr *) &groupSock,sizeof(groupSock));
		printf("packet sent\n");
	}
	close(sockfd);
}

struct rip* create_rip_header(){
	struct rip *ripE =(struct rip*)malloc(sizeof(struct rip));
	ripE->rip_cmd = 2;
	ripE->rip_vers = 2;
	return ripE;
}	

struct netinfo * create_rip_row(struct in_addr dstip, struct in_addr mask, struct in_addr nexthop, int metric){
	
	struct netinfo *ripH = (struct netinfo *)malloc(sizeof(struct netinfo));
	ripH->n_family = htons(AF_INET);
	ripH->n_tag = 0;
	ripH->n_dst = dstip.s_addr;
	ripH->n_mask = mask.s_addr;
	ripH->n_nhop = nexthop.s_addr;
	ripH->n_metric = metric;
	return ripH;
}

void send_rip(){
	struct sockaddr_in dest,netmask,nexthop;
	char *buffer = (char *)malloc(sizeof(char)*1500);
	int ptr =0;
	struct rip * rip_header;
	ptr = sizeof(struct rip);
	ARP_table *tmp_arp_head = arp_head;
	while(tmp_arp_head){
		rip_table *rip_head = tmp_arp_head->rip_link;
		if(rip_head == NULL) continue;
		rip_header = create_rip_header();
		memcpy(buffer,rip_header,sizeof(struct rip));
		free(rip_header);	

		while(rip_head){
			struct netinfo *rip_row = create_rip_row(rip_head->dst_ip, rip_head->mask, tmp_arp_head->other_ip, rip_head->metric);
			memcpy(buffer+ptr, rip_row, sizeof(struct netinfo));
			free(rip_row);
			ptr += sizeof(struct netinfo);
			rip_head = rip_head->next;
		}
		create_socket_send(buffer, ptr,tmp_arp_head->interface_ip);
		tmp_arp_head = tmp_arp_head->next;
	}	
}
