/*
 * iphdrchanges.c
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

//Parse IP address
int* parse_ip_address(char *ipaddr)
{   //printf("parse ip address\n");
    int i=-1, num = 0, p = 1,j=0;
    int *ipaddr_parse = malloc(sizeof(int)*4);
    char ch;
    do
    {   i++;
        ch = ipaddr[i];
        if(ch == '.' || ch == '\0')
        {   ipaddr_parse[j] = num;
            p = 1;
            num = 0;
            j++;
        }
        else
        {   num = num*p + (ch-48);
            if (p == 1) p = 10;
        }
    } while(ipaddr[i]!='\0');
    //printf("\n%d %d %d %d\n",ipaddr_parse[0], ipaddr_parse[1], ipaddr_parse[2], ipaddr_parse[3]);
    return ipaddr_parse;
}


uint16_t ip_checksum (struct ip *ip_hdr)
{   int *ipsrc_parse = parse_ip_address(inet_ntoa(ip_hdr->ip_src));
    int *ipdst_parse = parse_ip_address(inet_ntoa(ip_hdr->ip_dst));

     int sum = (((unsigned int)ip_hdr->ip_v<<12 | (unsigned int)ip_hdr->ip_hl<<8 | (ip_hdr->ip_tos)) +
            (ntohs(ip_hdr->ip_len))+
            (ntohs(ip_hdr->ip_id))+
            (ntohs(ip_hdr->ip_off))+
            ((ip_hdr->ip_ttl)<<8 | (ip_hdr->ip_p))+
            (ipsrc_parse[0]<<8 | ipsrc_parse[1])+
            (ipsrc_parse[2]<<8 | ipsrc_parse[3])+
            (ipdst_parse[0]<<8 | ipdst_parse[1])+
            (ipdst_parse[2]<<8 | ipdst_parse[3]));

    int chk_sum = ((sum & 0x0000ffff) + ((sum & 0xffff0000)>>16));

    return (uint16_t)(~chk_sum);
}
