/*
 * ethrchanges.h
 *
 *  Created on: Oct 1, 2014
 *      Author: kapil_000
 */

#ifndef ETHRCHANGES_H_
#define ETHRCHANGES_H_

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

int change_ether_addr_source(uint8_t pkt_type, struct ether_header *eth_hdr, char *ether_src);
int change_ether_addr_dest(uint8_t pkt_type, struct ether_header *eth_hdr, char *ether_dst);
uint8_t *parse_ether_address(char *ether_addr_str);


#endif /* ETHRCHANGES_H_ */
