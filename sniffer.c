#include "sniffer.h"
#include "route_table.h"   
#include "pktinjection.h"
#include "iphdrchanges.h"
#include "arp_table.h"

interfaces *head_iface = NULL;

typedef struct customIcmp{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short identifier;
    unsigned short sequence;
    char data[28]; /* we're going to send data MTU bytes at a time */
}customIcmp;

u_char *modify_packet(u_char *pkt_ptr,int pkt_type, int len,uint8_t* ether_src, uint8_t* ether_dst)
{   
	//printf("inside modify packet\n");
    u_char *timeExceedePacket =(char *)malloc(sizeof(char)*(70));
    memset(timeExceedePacket,0,70); 
    customIcmp *myicmp= (struct customIcmp *)malloc(sizeof(struct customIcmp));
    memset(myicmp,0,36);
    struct ether_header *eth_hdr = (struct ether_header *)pkt_ptr;     //Pointer to ethernet
    struct ip *ip_hdr = (struct ip *)(pkt_ptr + ETHERNET_HEADER_LEN); //point to an IP header structure

    int i = 0;
	for(i=0;i<6;i++){
        eth_hdr->ether_shost[i] = ether_src[i];
        eth_hdr->ether_dhost[i] = ether_dst[i];
	}
    if(pkt_type==1){
        //change the src ip and dst ipaddr
        struct in_addr inp;
        inp=ip_hdr->ip_src;
        ip_hdr->ip_src=ip_hdr->ip_dst;
        ip_hdr->ip_dst=inp;
        printf("Changing icmp Header\n");
        struct icmphdr *icmp_hdr = (struct icmphdr *)(pkt_ptr+14+20);
        icmp_hdr->type=0;
        icmp_hdr->code=0;
        icmp_hdr->checksum=0; 
        unsigned short csumicmp= htons(icmpChecksum((unsigned short *)icmp_hdr,len));
        icmp_hdr->checksum=htons(csumicmp);
    }
    if(pkt_type==2){
        //change the src ip and dst ipaddr
        memcpy(timeExceedePacket,(char*)eth_hdr,14);
        memcpy(myicmp->data,ip_hdr,28);
        struct in_addr inp;
        inp=ip_hdr->ip_src;
	ARP_table *tmp_arp_table = arp_head;
        while(tmp_arp_table){
			if((tmp_arp_table->interface_mac_addr[0] == ether_src[0]) && (tmp_arp_table->interface_mac_addr[1] == ether_src[1]) && (tmp_arp_table->interface_mac_addr[2] == ether_src[2]) && (tmp_arp_table->interface_mac_addr[3] == ether_src[3]) && (tmp_arp_table->interface_mac_addr[4] == ether_src[4]) && (tmp_arp_table->interface_mac_addr[5] == ether_src[5]) ){
				ip_hdr->ip_src = tmp_arp_table->interface_ip;
				break;
			}
		}
        ip_hdr->ip_dst=inp;
        ip_hdr->ip_p=1;
        ip_hdr->ip_len=htons(56);
        printf("Changing icmp Header for type 2\n");
        myicmp->type=11;  
        myicmp->code=0;
        myicmp->checksum=0; 
        unsigned short csumicmp= htons(icmpChecksum((unsigned short *)myicmp,36));
        myicmp->checksum=htons(csumicmp);
        memcpy(timeExceedePacket+14+20,(char *)myicmp,36); //copy whole new icmp
    }
    if(pkt_type==3){
        memcpy(timeExceedePacket,(char*)eth_hdr,14);
        memcpy(myicmp->data,ip_hdr,28);
        struct in_addr inp;
        inp=ip_hdr->ip_src;
	ARP_table *tmp_arp_table = arp_head;
        while(tmp_arp_table){
			if((tmp_arp_table->interface_mac_addr[0] == ether_src[0]) && (tmp_arp_table->interface_mac_addr[1] == ether_src[1]) && (tmp_arp_table->interface_mac_addr[2] == ether_src[2]) && (tmp_arp_table->interface_mac_addr[3] == ether_src[3]) && (tmp_arp_table->interface_mac_addr[4] == ether_src[4]) && (tmp_arp_table->interface_mac_addr[5] == ether_src[5]) ){
				ip_hdr->ip_src = tmp_arp_table->interface_ip;
				break;
			}
		}
        ip_hdr->ip_dst=inp;
        ip_hdr->ip_p=1;
        ip_hdr->ip_len=htons(56);
        printf("Changing icmp Header for type 3\n");
        myicmp->type=3;  
        myicmp->code=1;
        myicmp->checksum=0; 
        unsigned short csumicmp= htons(icmpChecksum((unsigned short *)myicmp,36));
        myicmp->checksum=htons(csumicmp);
        memcpy(timeExceedePacket+14+20,(char *)myicmp,36); //copy whole new icmp
    }
     if(pkt_type==4){
        memcpy(timeExceedePacket,(char*)eth_hdr,14);
        memcpy(myicmp->data,ip_hdr,28);
        struct in_addr inp;
        inp=ip_hdr->ip_src;
		ip_hdr->ip_src = ip_hdr->ip_dst; 
        ip_hdr->ip_dst=inp;
        ip_hdr->ip_p=1;
        ip_hdr->ip_len=htons(56);
        printf("Changing icmp Header for type 4\n");
        myicmp->type=3;  
        myicmp->code=3;
        myicmp->checksum=0; 
        unsigned short csumicmp= htons(icmpChecksum((unsigned short *)myicmp,36));
        myicmp->checksum=htons(csumicmp);
        memcpy(timeExceedePacket+14+20,(char *)myicmp,36); //copy whole new icmp
    }

	//Change the ttl and checksum
    ip_hdr->ip_ttl-=1;
    if(ip_hdr->ip_ttl==0){
        ip_hdr->ip_ttl=64;
    }
    ip_hdr->ip_sum = (htons)(ip_checksum(ip_hdr));
    if(pkt_type == 2  || pkt_type == 3 || pkt_type == 4){
        memcpy(timeExceedePacket+14,ip_hdr,20);
        return timeExceedePacket;
    }
    //printf("end of modify packet\n");
    return pkt_ptr;
}

void sniff_open(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	u_char *pkt_ptr = (u_char *)packet;
	
	int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];
	int ether_offset = 0;
	if (ether_type == ETHER_TYPE_IP)
		ether_offset = 14;
	else if (ether_type == ETHER_TYPE_8021Q)
		ether_offset = 18;

	struct ether_header *eptr;
	eptr = (struct ether_header *) pkt_ptr;
	
	//fprintf(stdout,"ethernet header source: %s\n"
	 //         ,ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
	//fprintf(stdout," destination: %s\n "
	//                ,ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));
	if(ether_offset == 0)
		goto out;	
	pkt_ptr += ether_offset;
	if(ether_type == ETHER_TYPE_ARP)
		printf("ARP captured\n");
	else{
		printf("Tapped a packed\n");
		struct ip *ip_hdr = (struct ip *)pkt_ptr;
		char *src_ip = (char *)calloc(sizeof(char),16);
		memcpy(src_ip, inet_ntoa(ip_hdr->ip_src), strlen(inet_ntoa(ip_hdr->ip_src)));
		char *dst_ip = (char *)calloc(sizeof(char), 16);
		memcpy(dst_ip, inet_ntoa(ip_hdr->ip_dst), strlen(inet_ntoa(ip_hdr->ip_dst)));
		if(!strcmp(inet_ntoa(ip_hdr->ip_dst), "224.0.0.9")){
			printf("This is RIPppppppppppppppppppppp\n");
			//parse_rip((u_char *)packet);
			printf("##############RIP PARSED #####################\n");
			//return;
			goto out;
		}
		if(!strncmp(src_ip,"192.168",7) || !strncmp(dst_ip,"192.168",7)){
			printf("Into 192\n");
			goto out;
		}
		int flag_dst = 0;
		ARP_table *tmp_arp_table = arp_head;
		while(tmp_arp_table){
			if(tmp_arp_table->interface_ip.s_addr == ip_hdr->ip_dst.s_addr){
				flag_dst = 1;
				break;
			}
			tmp_arp_table= tmp_arp_table->next;
		}
		uint8_t *src_mac = (uint8_t*)malloc(sizeof(uint8_t)*6);
		uint8_t *dst_mac = (uint8_t *)malloc(sizeof(uint8_t)*6);
		struct icmphdr *icmp_hdr = (struct icmphdr *) (struct icmp *)(packet+14+20);
		u_char *ptr;	
		//Packet Type ICMP
		int ttl_old=ip_hdr->ip_ttl;
		if(ip_hdr->ip_p==IP_PROTO_ICMP && flag_dst){
			printf("ICMP PACKET\n");
			//strcpy(src_mac, (const struct ether_addr *)&eptr->ether_dhost);
			//strcpy(dst_mac, (const struct ether_addr *)&eptr->ether_shost));
			int i=0;
			for(i=0;i<6;i++){
				src_mac[i]=eptr->ether_dhost[i];
				dst_mac[i]=eptr->ether_shost[i];
			}
			//memcpy(src_mac, eptr->ether_dhost, 6);
			//memcpy(dst_mac, eptr->ether_shost, 6);
			switch(icmp_hdr->type){
               	case 8:
					printf("This is an echo request ICMP\n");
                   	//u_char *packet_copy = (u_char *)packet;
					//u_char *ptr = modify_packet(packet_copy,2,pkthdr->len, &eptr->ether_dhost, &eptr->ether_shost);
					u_char *ptr = modify_packet((u_char *)packet,1,pkthdr->len, src_mac, dst_mac);
					tmp_arp_table = arp_head;
					while(tmp_arp_table){
						if((tmp_arp_table->interface_mac_addr[0] == src_mac[0]) && (tmp_arp_table->interface_mac_addr[1] == src_mac[1]) && (tmp_arp_table->interface_mac_addr[2] == src_mac[2]) && (tmp_arp_table->interface_mac_addr[3] == src_mac[3]) && (tmp_arp_table->interface_mac_addr[4] == src_mac[4]) && (tmp_arp_table->interface_mac_addr[5] == src_mac[5]) ){
							pcap_inject ( tmp_arp_table->handle, ptr, pkthdr->len );
							//packet_injection_new(tmp_iface->handle, pkthdr, ptr);
							break;
						}
						tmp_arp_table= tmp_arp_table->next;
					}
                break;
                default:
                    break;
            }
		} 
		else if(ip_hdr->ip_ttl == 1 && !flag_dst){
			//strcpy(src_mac, (const struct ether_addr *)&eptr->ether_dhost);
			//strcpy(dst_mac, (const struct ether_addr *)&eptr->ether_shost);
		
			int i=0;
			for(i=0;i<6;i++){
				src_mac[i]=eptr->ether_dhost[i];
				dst_mac[i]=eptr->ether_shost[i];
			}
			//IP_table *rt_details = get_IP_table_row(inet_ntoa(ip_hdr->ip_dst));
			ptr = modify_packet((u_char *)packet,2,pkthdr->len, src_mac, dst_mac);
			tmp_arp_table = arp_head;
			while(tmp_arp_table){
				if((tmp_arp_table->interface_mac_addr[0] == src_mac[0]) && (tmp_arp_table->interface_mac_addr[1] == src_mac[1]) && (tmp_arp_table->interface_mac_addr[2] == src_mac[2]) && (tmp_arp_table->interface_mac_addr[3] == src_mac[3]) && (tmp_arp_table->interface_mac_addr[4] == src_mac[4]) && (tmp_arp_table->interface_mac_addr[5] == src_mac[5]) ){
					pcap_inject (tmp_arp_table->handle, ptr, 70);
					break;
				}
				tmp_arp_table= tmp_arp_table->next;
			}
   		} 
		else{
			if(flag_dst && ip_hdr->ip_ttl == 1){
				printf("Type 44444444444444\n");
				int i=0;
				for(i=0;i<6;i++){
					src_mac[i]=eptr->ether_dhost[i];
					dst_mac[i]=eptr->ether_shost[i];
				}
				ptr = modify_packet((u_char *)packet,4,pkthdr->len, src_mac, dst_mac); // Destination unreachable
				tmp_arp_table = arp_head;
				while(tmp_arp_table){
					if((tmp_arp_table->interface_mac_addr[0] == src_mac[0]) && (tmp_arp_table->interface_mac_addr[1] == src_mac[1]) && (tmp_arp_table->interface_mac_addr[2] == src_mac[2]) && (tmp_arp_table->interface_mac_addr[3] == src_mac[3]) && (tmp_arp_table->interface_mac_addr[4] == src_mac[4]) && (tmp_arp_table->interface_mac_addr[5] == src_mac[5]) ){
						pcap_inject (tmp_arp_table->handle, ptr, 70);
						break;
					}
					tmp_arp_table= tmp_arp_table->next;
				}
			}	
			else if(flag_dst) goto out;
			else{
				//Packet Type is data(udp/tcp)
				//printf("passing ------------\n ");
				//IP_table *rt_details = get_IP_table_row(inet_ntoa(ip_hdr->ip_dst));
				ARP_table *arp_node_tosend = get_ARP_table_row(ip_hdr->ip_dst);
				if(arp_node_tosend == NULL){
					int i=0;
					for(i=0;i<6;i++){
						src_mac[i]=eptr->ether_dhost[i];
						dst_mac[i]=eptr->ether_shost[i];
					}
					ptr = modify_packet((u_char *)packet,3,pkthdr->len, src_mac, dst_mac);
					tmp_arp_table = arp_head;
					while(tmp_arp_table){
						if((tmp_arp_table->interface_mac_addr[0] == src_mac[0]) && (tmp_arp_table->interface_mac_addr[1] == src_mac[1]) && (tmp_arp_table->interface_mac_addr[2] == src_mac[2]) && (tmp_arp_table->interface_mac_addr[3] == src_mac[3]) && (tmp_arp_table->interface_mac_addr[4] == src_mac[4]) && (tmp_arp_table->interface_mac_addr[5] == src_mac[5]) ){
							pcap_inject (tmp_arp_table->handle, ptr, 70);
							break;
						}
						tmp_arp_table= tmp_arp_table->next;
					}
				}
				else{
					src_mac = arp_node_tosend->interface_mac_addr;
					dst_mac = arp_node_tosend->other_mac_addr_in_uint;
					ptr = modify_packet((u_char *)packet,0,pkthdr->len, src_mac, dst_mac);
					pcap_inject(arp_node_tosend->handle, ptr, pkthdr->len);
				//tmp_arp_table = arp_head;
				//while(tmp_arp_table){
				//	if(!strcmp(tmp_arp_table->if_to_send,rt_details->iface)){
				//		src_mac = tmp_arp_table->interface_mac_addr;
				//		dst_mac = tmp_arp_table->other_mac_addr_in_uint;
				//		ptr = modify_packet(packet,0,pkthdr->len, src_mac, dst_mac);
				//		pcap_inject ( tmp_arp_table->handle, ptr, pkthdr->len );
				//		break;
				//	}
				//	tmp_arp_table = tmp_arp_table->next;
				//}
				}
			}
		} 
	}
	out:;
}
//int thread_break = 0;
void *sniff_and_send(void *arg){
	printf("sniff and send\n");
	ARP_table *i = (ARP_table *)arg;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	printf("THe interfae name %s\n", i->if_to_send);
	handle=pcap_open_live(i->if_to_send, 65536, 1, -1, errbuf);
	if (handle == NULL) {
		fprintf(stderr,"Couldn't open interface %s: %s\n", i->if_to_send, errbuf);
		exit(1);
	}
pcap_t *handle_out;
	handle_out = pcap_open_live(i->if_to_send, 65536, 1, -1, errbuf);
	i->handle = handle_out;
	//printf("Handle --------------- %d\n",(int)handle);
	if (handle_out == NULL) {
		fprintf(stderr,"Couldn't open interface %s: %s\n", i->if_to_send, errbuf);
		exit(1);
	}
//char *if_got = (char *)malloc(10);
	//strcpy(if_got, i->if_to_send);
	//printf("%d direction",pcap_setdirection(handle,PCAP_D_IN));
	if(pcap_setdirection(handle,PCAP_D_IN) == -1) printf("Error in setting direction:%d", errno);
	//if(thread_break == 0){ thread_break=1;while(1){}}
	//else{
	int pl = pcap_loop(handle,-1,sniff_open, NULL);
	printf("###################################OUT#######################\n");
	if(pl < 0){
		printf("pcap loop error %d",errno);
		exit(0);
	}
	printf("###########################EXITING#################\n");
	//}
	pcap_close(handle);
	return NULL;
}
