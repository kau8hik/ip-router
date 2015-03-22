/*
 * pktinjection.c
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

//Inject packets based on handler or interface name
void packet_injection(char * user, const struct pcap_pkthdr* packet_header, const u_char* packet_data){

    char* inject_interface = user;
    char errbuf [ PCAP_ERRBUF_SIZE ];
    pcap_t* inject_int_desc;
    /* Setup the Injection Interface */
    if ( ( inject_int_desc = pcap_open_live ( inject_interface, BUFSIZ,
                             1, -1, errbuf ) ) == NULL )
    {
        printf ( "\nError: %s\n", errbuf );
        exit ( 1 );
    }

    pcap_inject ( inject_int_desc, packet_data, packet_header->len );

    pcap_close ( inject_int_desc );
}


void packet_injection_new(pcap_t* inject_int_desc, const struct pcap_pkthdr* packet_header, const u_char* packet_data)
{
    pcap_inject ( inject_int_desc, packet_data, packet_header->len );

}
