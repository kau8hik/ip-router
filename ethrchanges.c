/*
 * ethrchanges.c

 *
 *  Created on: Oct 1, 2014
 *      Author: kapil_000
 */
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <ctype.h>
uint8_t *parse_ether_address(char *ether_addr_str)
{   
	//printf("parse ether address\n");
    int i =-1,c,j=0;
    char ch;
    uint8_t num=0, *ether_addr = malloc(sizeof(int)*6);
    do
    {   i++;
        ch = ether_addr_str[i];
	ch = tolower(ch);
        if(ch == ':' || ch == '\0')
        {   ether_addr[j] = num;
            num = 0;
            j++;
        }
        else
        {   c = (ch>57)? ch-87 : ch-48;
            num = num*16 + c;
        }
    } while(ether_addr_str[i] != '\0');
    return ether_addr;
}

int change_ether_addr_source(uint8_t pkt_type, struct ether_header *eth_hdr, char *ether_src)
{   //printf("change_ether_addr_source\n");

    printf("%s\n",ether_src);
    uint8_t *ether_source = parse_ether_address(ether_src);
    int i;
    for(i=0;i<6;i++)
        eth_hdr->ether_shost[i] = ether_source[i];

    //Result will be stored in eth_hdr
}

int change_ether_addr_dest(uint8_t pkt_type, struct ether_header *eth_hdr, char *ether_dst)
{   //printf("inside change ether address dest\n");
    uint8_t *ether_dest = parse_ether_address(ether_dst);
    int i;
    for(i=0;i<6;i++)
        eth_hdr->ether_dhost[i] = ether_dest[i];
    //Result will be stored in eth_hdr
}


