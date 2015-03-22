/*
 * icmpchanges.h
 *
 *  Created on: Oct 1, 2014
 *      Author: kapil_000
 */

#ifndef ICMPCHANGES_H_
#define ICMPCHANGES_H_

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

unsigned short icmpChecksum(unsigned short *buffer, int length);

#endif /* ICMPCHANGES_H_ */
