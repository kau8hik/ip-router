/*
 * iphdrchanges.h
 *
 *  Created on: Oct 1, 2014
 *      Author: kapil_000
 */

#ifndef IPHDRCHANGES_H_
#define IPHDRCHANGES_H_



int* parse_ip_address(char *ipaddr);
uint16_t ip_checksum (struct ip *ip_hdr);


#endif /* IPHDRCHANGES_H_ */
