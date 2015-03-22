/*
 * pktinjection.h
 *
 *  Created on: Oct 1, 2014
 *      Author: kapil_000
 */

#ifndef PKTINJECTION_H_
#define PKTINJECTION_H_
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

void packet_injection(char * user, const struct pcap_pkthdr* packet_header, const u_char* packet_data);
void packet_injection_new(pcap_t* inject_int_desc, const struct pcap_pkthdr* packet_header, const u_char* packet_data);


#endif /* PKTINJECTION_H_ */
