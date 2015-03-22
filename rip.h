#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include "arp_table.h"
struct netauth {
	u_int16_t   a_family;		/* always RIP_AF_AUTH */
	u_int16_t   a_type;
#define	    RIP_AUTH_NONE   0
#define	    RIP_AUTH_PW	    htons(2)	/* password type */
#define	    RIP_AUTH_MD5    htons(3)	/* Keyed MD5 */
	union {
#define	    RIP_AUTH_PW_LEN 16
	    u_int8_t    au_pw[RIP_AUTH_PW_LEN];
	    struct a_md5 {
		int16_t	md5_pkt_len;	/* RIP-II packet length */
		int8_t	md5_keyid;	/* key ID and auth data len */
		int8_t	md5_auth_len;	/* 16 */
		u_int32_t md5_seqno;	/* sequence number */
		u_int32_t rsvd[2];	/* must be 0 */
#define	    RIP_AUTH_MD5_KEY_LEN   RIP_AUTH_PW_LEN
#define	    RIP_AUTH_MD5_HASH_XTRA (sizeof(struct netauth)-sizeof(struct a_md5))
#define	    RIP_AUTH_MD5_HASH_LEN  (RIP_AUTH_MD5_KEY_LEN+RIP_AUTH_MD5_HASH_XTRA)
	    } a_md5;
	} au;
};

struct netinfo {
	u_int16_t   n_family;
#define	    RIP_AF_INET	    htons(AF_INET)
#define	    RIP_AF_UNSPEC   0
#define	    RIP_AF_AUTH	    0xffff
	u_int16_t   n_tag;		/* optional in RIPv2 */
	u_int32_t   n_dst;		/* destination net or host */
#define	    RIP_DEFAULT	    0
	u_int32_t   n_mask;		/* netmask in RIPv2 */
	u_int32_t   n_nhop;		/* optional next hop in RIPv2 */
	u_int32_t   n_metric;		/* cost of route */
};

struct rip {
	u_int8_t    rip_cmd;		/* request/response */
	u_int8_t    rip_vers;		/* protocol version # */
	u_int16_t   rip_res1;		/* pad to 32-bit boundary */
	union {				/* variable length... */
	    struct netinfo ru_nets[1];
	    int8_t    ru_tracefile[1];
	    struct netauth ru_auth[1];
	} ripun;
#define	rip_nets	ripun.ru_nets
#define rip_auths	ripun.ru_auth
#define	rip_tracefile	ripun.ru_tracefile
};

typedef struct rip_table{
	struct in_addr dst_ip, mask;
	int metric, cnt;
	struct rip_table *next;
}rip_table;

#define	RIPCMD_REQUEST		1	/* want info */
#define	RIPCMD_RESPONSE		2	/* responding to request */
#define	RIPCMD_TRACEON		3	/* turn tracing on */
#define	RIPCMD_TRACEOFF		4	/* turn it off */

void *send_rip_update();

ARP_table * get_ARP_table_row(struct in_addr);

void parse_rip(u_char *Buffer);

void create_socket_send(char *payload, int payload_len, struct in_addr ip_tosend);

struct rip * create_rip_header();

struct netinfo * create_rip_row(struct in_addr dstip, struct in_addr mask, struct in_addr nexthop, int metric);

void send_rip();
