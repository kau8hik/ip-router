#include <stdio.h>
#include <signal.h>     /* for signal */
#include <sys/time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include "rip.h"
#include "route_table.h"
#include "sniffer.h"

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define ETHER_TYPE_ARP (0x0806)
#define SIZE_ETHERNET 14
#define ETHERNET_HEADER_LEN 14
#define IP_PROTO_ICMP 1 

int main(){
	parse_ARP_table();
	populate_IP_table();
	int thread_cnt = -1;
	ARP_table *i_loop =arp_head;
	while(i_loop){
		thread_cnt++;
		i_loop = i_loop -> next;
	}
	pthread_t thread_id[thread_cnt+1];
	int loopCount=thread_cnt;
	ARP_table *tmp = arp_head;
	while(loopCount >= 0){
		int tc = pthread_create(&thread_id[loopCount], NULL, &sniff_and_send, tmp);
		if(tc != 0)
			printf("Error creating thread %d\n", errno);
		loopCount--;
		tmp = tmp->next;
	}
	 signal(SIGALRM, send_rip_update);
	 alarm( 1 );
	int thr = pthread_create(&thread_id[0],NULL, &send_rip_update,NULL);
	if(thr != 0)
				printf("Error while creating rip thread\n");
	int j;
	for (j = thread_cnt; j >= 0; j--) {
			printf("Thread %d closed\n",j);
	       int s = pthread_join(thread_id[j],NULL);
	       if (s != 0)	printf("Error in joining %d", errno);
	}
	return 1;
}
