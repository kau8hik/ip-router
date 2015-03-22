/*
 * icmpchanges.c
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

unsigned short icmpChecksum(unsigned short *buffer, int length)
{
    unsigned long sum;
    for (sum=0; length>1; length-=2) // sizeof() returns number of bytes, we're interested in number of words
        sum += *buffer++;   // add 1 word of buffer to sum and proceed to the next

    // we may have an extra byte
    if (length==1)
        sum += (char)*buffer;

    sum = (sum >> 16) + (sum & 0xFFFF);  // add high 16 to low 16
    sum += (sum >> 16);          // add carry
    return ~sum;
}


