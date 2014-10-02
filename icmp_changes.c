//gcc fisrtpacketInjection.c -lpthread -lpcap -g


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
#include <netinet/ip_icmp.h>
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define ETHER_TYPE_ARP (0x0806)
#define SIZE_ETHERNET 14
#define ETHERNET_HEADER_LEN 14
#define IP_PROTO_ICMP 1 

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

typedef struct interfaces{
        char * device_name;
        char * device_addr;
        char * device_mask;
        struct interfaces *next;
}interfaces;
//Custom Functions Kapil 
void print_packet(const u_char* packet);
void packet_injection(char * user, const struct pcap_pkthdr* packet_header, const u_char* packet_data);
u_char* modify_packet(u_char *pkt_ptr,int pkt_type, int len,char* ether_src, char* ether_dst);
int change_ether_addr_dest(uint8_t pkt_type, struct ether_header *eth_hdr,char* ether_dst);
int change_ether_addr_source(uint8_t pkt_type, struct ether_header *eth_hdr, char* ether_src);
uint8_t *parse_ether_address(char *ether_addr_str);
uint16_t ip_checksum(struct ip *ip_hdr);
int* parse_ip_address(char *);

//ICMP
void printIcmp(const char *packet, int len);
unsigned short icmpChecksum(unsigned short *buffer, int length);


interfaces *getAllInterfaceNames(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    int status = pcap_findalldevs(&alldevs, errbuf);
    if(status != 0) {
        printf("%s\n", errbuf);
        exit (1);
    }
    interfaces * head = NULL;
    interfaces * tail = NULL;
        pcap_if_t *d;
    for(d=alldevs; d!=NULL; d=d->next) {
                pcap_addr_t *a;
        for(a=d->addresses; a!=NULL; a=a->next) {
            if(a->addr->sa_family == AF_INET && d->flags != PCAP_IF_LOOPBACK){
                interfaces *node = (interfaces *)malloc(sizeof(interfaces));
                                node->device_name = d->name;
                                node->device_addr = inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr);
                                node->device_mask = inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr);
                                node->next = NULL;
                                if(head == NULL){
                                        head = node;
                                        tail = node;
                                }
                                else{
                                        tail->next = node;
                                        tail = node;
                                }
                                
                }
        }
        }
    return head;
}

void getMacAddr(unsigned char MAC_str[13], char *interface_name){
    #define HWADDR_len 6
        int s,i;
        struct ifreq ifr;
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if(s == -1)
                printf("Unable to create socket %d",errno);
        strcpy(ifr.ifr_name, interface_name);
        ioctl(s, SIOCGIFHWADDR, &ifr);
        for (i=0; i<HWADDR_len; i++)
        sprintf(&MAC_str[i*2],"%02X",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
        MAC_str[12]='\0';
}


//All Processing Happend here!
void sniff_open(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){
        u_char *pkt_ptr = (u_char *)packet;
       // printf("Tapped a packed ");
        int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];
        int ether_offset = 0;
    

    
        if (ether_type == ETHER_TYPE_IP)
            ether_offset = 14;
        else if (ether_type == ETHER_TYPE_8021Q)
            ether_offset = 18;

        struct ether_header *eptr;
         eptr = (struct ether_header *) pkt_ptr;

        fprintf(stdout,"ethernet header source: %s\n"
                    ,ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
        char *mySrc= ether_ntoa((const struct ether_addr *)&eptr->ether_shost);
       // printf("---------------------------------------Packet source is : %s\n",mySrc);
        fprintf(stdout," destination: %s\n "
                          ,ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));
         struct ether_header *mytest = (struct ether_header *)packet; 



        pkt_ptr += ether_offset;
        if(ether_type == ETHER_TYPE_ARP){
                printf("ARP captured\n");

        }
        else{
        //Get the packet type (ICMP/DATA(udp/tcp))
                struct ip *ip_hdr = (struct ip *)pkt_ptr;
                //pkt_ptr+=(ip_hdr->ip_hl*4);
        //char *src_ip = (char *)malloc(sizeof(char)*32);
        //Why memcopy here?
                //memcpy(src_ip,inet_ntoa(ip_hdr->ip_src),strlen(inet_ntoa(ip_hdr->ip_src)));
                //char *dst_ip = inet_ntoa(ip_hdr->ip_dst);
                //printf("The src ip address is--- %s\n", src_ip);
                //printf("The dst ip address is--- %s\n", dst_ip);
        //Packet Type ICMP
        if(ip_hdr->ip_p==IP_PROTO_ICMP){
            printf("ICMP PACKET\n");
            //print_packet(packet);       

            printf("Injecting packet\n");
            //print_packet(packet);
            //pkt_ptr += 20;

            struct icmphdr *icmp_hdr = (struct icmphdr *) (struct icmp *)(packet+14+20);
            //struct icmp *icmp_hdr = (struct icmp *)(packet+14+20);
            
            //printf("ICMP source = %s destination = %s\n", src_ip, dst_ip);
            printf("Length of ICMP packet is: %d\n",pkthdr->len);
            printIcmp(packet, pkthdr->len);

            switch(icmp_hdr->type){
                case 0:
                        if(icmp_hdr->code == 0)
                            printf("This is an echo reply\n");
                        break;
                case 3:
                        if(icmp_hdr->code == 0){
                            printf("This is network unreachable ICMP\n");
                            break;
                        }
                        else if(icmp_hdr->code == 1){
                            printf("This is a host unreachable ICMP\n");
                            break;
                        }  
                        else if(icmp_hdr->code == 3){
                             printf("This is a port unreachable ICMP\n");
                        break;
                        }
                        else if(icmp_hdr->code == 7){
                            printf("This is a Dest Host Unknown ICMP\n");
                            break;
                        }
                        else
                            break;
                case 8:
                        printf("This is an echo request ICMP\n");
                        //Send reply    
                                                                         //src_mac          dst_mac 
                         u_char *packet_copy = (u_char *)packet;                                        //src_mac          dst_mac
                         u_char *ptr = modify_packet(packet_copy,2,pkthdr->len, "00:0c:29:68:69:27","00:50:56:f4:ae:15");
                         packet_injection("eth0",pkthdr, ptr);
                        break;
                case 11: 
                        if(icmp_hdr->code == 0){
                            printf("This is a TTL exceeded ICMP\n");
                            u_char *packet_copy = (u_char *)packet;
                            u_char *ptr = modify_packet(packet_copy,2,pkthdr->len, "00:0c:29:68:69:27","00:50:56:f4:ae:15");
                            packet_injection_timeExceede("eth0",pkthdr, ptr)
                            //So we need to send the echo reply
                            break;
                        }    
                default:
                        break;
            }
            //packet_injection("eth0",pkthdr, packet);
            //printf("Packet Type is: %d\n",ip_hdr->ip_p);
            //Cases to handle
            /*  1.Check destination -->reply to this icmp
                2.Check ttl
                3.Else forward packet accordingly

            */                                                  //src_mac          dst_mac
        //u_char *packet_copy = (u_char *)packet;                                        //src_mac          dst_mac
        //u_char *ptr = modify_packet(packet_copy,0,pkthdr->len, "00:04:23:ae:d0:87","00:0e:0c:68:a7:43");
        //packet_injection("eth2",pkthdr, ptr);

        } else {
            //Packet Type is data(udp/tcp)
            printf("NOT ICMP\n");
            print_packet(packet);           
            

        } 

        //function to check the dst_ip and find the destination network
        //function to check the destination network and get the next_hop interface and mac.
        //function to send the packet after modifaction.

        
                
        }
        return ;
}

void *sniff_and_send(void *arg){

        printf("Into thread\n");
        interfaces *i = (interfaces *)arg;
        char errbuf[PCAP_ERRBUF_SIZE];
        static pcap_t *handle;
        int pcap_setdirectionValue;
        printf("The interfae name %s\n", i->device_name);
        //handle=pcap_open_live(i->device_name, BUFSIZ, 1, 1000, errbuf);
        handle=pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
        /*
        pcap_setdirectionValue=pcap_setdirection(handle, PCAP_D_IN);
        if(pcap_setdirectionValue==-1){
            fprintf(stderr, "Not able to set the direction\n");
        }
        */
    if (handle == NULL) {
        fprintf(stderr,"Couldn't open interface %s: %s\n", i->device_name, errbuf);
        exit(1);
    }
    int pl = pcap_loop(handle,-1,sniff_open,NULL);
    if(pl < 0){
        printf("pcap loop error %d",errno);
        pcap_close(handle);
    }    
}

int main(){
        interfaces *i = getAllInterfaceNames();
        int thread_cnt = 0;
        interfaces *i_loop;
        i_loop = i;
        while(i_loop){
                thread_cnt++;
        printf("name : %s\n", i_loop->device_name);
                i_loop = i_loop -> next;
        }
    printf("Thread Count %d\n",thread_cnt);
        pthread_t thread_id[thread_cnt];
        //thread_cnt = 0;
    int loopCount=thread_cnt;
    printf("Loop Count: %d\n",loopCount);
        while(loopCount){
                unsigned char mac[13];
                getMacAddr(mac,i->device_name);
                int tc = pthread_create(&thread_id[loopCount], NULL, &sniff_and_send, i);
                if(tc != 0)
                                printf("Error creating thread %d\n", errno);
                //thread_cnt++;
        loopCount--;
                i = i -> next;
                printf("The mac is %s \n",mac);
        }
        int j;
    pthread_join(thread_id[1],NULL);
        //for (j = 1; j < thread_cnt; j++) {
         //       int s = pthread_join(thread_id[j],NULL);
         //       if (s != 0)
         //               printf("Error in joining %d", errno);
        //}
        return 1;
}

void print_packet(const u_char* packet){
    printf("-----------------INSIDE------------------\n");
    u_char *pkt_ptr =NULL;
    pkt_ptr= (u_char *)packet;
    int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];
    int ether_offset = 0;
    if (ether_type == ETHER_TYPE_IP)
            ether_offset = 14;
        else if (ether_type == ETHER_TYPE_8021Q)
            ether_offset = 18;
        struct ether_header *eptr;
        eptr = (struct ether_header *) pkt_ptr;
        //fprintf(stdout,"ethernet header source: %s\n" ,ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
        //fprintf(stdout," destination: %s\n ",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));
        //pkt_ptr+=(ip_hdr->ip_hl*4);
        struct ip *ip_hdr = (struct ip *)(pkt_ptr+14);
       
    char *src_ip = (char *)malloc(sizeof(char)*32);
        memcpy(src_ip,(inet_ntoa(ip_hdr->ip_src)),strlen(inet_ntoa(ip_hdr->ip_src)));
        //char *src_ip = inet_ntoa(ip_hdr->ip_src);
        char *dst_ip =( inet_ntoa(ip_hdr->ip_dst));
        printf("The src ip address is %s\n", src_ip);
        printf("The dst ip address is %s\n", dst_ip);

}

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
    
    //pcap_inject ( inject_int_desc, packet_data, packet_header->len ); --kapil
    pcap_inject ( inject_int_desc, packet_data, 126);
    printf("Sent Injected packet\n");
    
    pcap_close ( inject_int_desc );
}

void packet_injection_timeExceede(char * user, const struct pcap_pkthdr* packet_header, const u_char* packet_data){

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
    
    //pcap_inject ( inject_int_desc, packet_data, packet_header->len ); --kapil
    pcap_inject ( inject_int_desc, packet_data, 126);
    printf("Sent Injected packet\n");
    
    pcap_close ( inject_int_desc );
}


u_char *modify_packet(u_char *pkt_ptr,int pkt_type, int len,char* ether_src, char* ether_dst)
{   //printf("inside modify packet\n");
    
    if(pkt_type==2){
        u_char *timeExceedePacket =(char *)malloc(sizeof(char)*(126));
        memset(timeExceedePacket,0,126); 
    }
 
    struct ether_header *eth_hdr = (struct ether_header *)pkt_ptr;     //Pointer to ethernet
    struct ip *ip_hdr = (struct ip *)(pkt_ptr + ETHERNET_HEADER_LEN); //point to an IP header structure
    
    //CHange the src_mac/ dst_mac 
    change_ether_addr_source(pkt_type, eth_hdr, ether_src);
    change_ether_addr_dest(pkt_type, eth_hdr, ether_dst);

    //If packet is icmp echo --interchange the src_ip and dst_ip
    //pkt_type==1 =>ICMP echo
    if(pkt_type==1){
        //change the src ip and dst ipaddr
        //char* srcip;
        //srcip=(char*)malloc(32);
        struct in_addr inp;
        inp=ip_hdr->ip_src;
        ip_hdr->ip_src=ip_hdr->ip_dst;
        ip_hdr->ip_dst=inp;
        ///change the icmp code and type for reply
        printf("Changing icmp Header\n");
        //struct icmphdr *icmp_hdr = (struct icmphdr *) (struct icmp *)(pkt_ptr+14+20);
        struct icmphdr *icmp_hdr = (struct icmphdr *)(pkt_ptr+14+20);
        icmp_hdr->type=0;
        icmp_hdr->code=0;
        //printf("TYPE: %d\n",icmp_hdr->type);
        //printf("Code: %d\n",icmp_hdr->code);
        //printf("Checksum: %x\n",ntohs(icmp_hdr->checksum));
        icmp_hdr->checksum=0; 
        unsigned short csumicmp= htons(icmpChecksum((unsigned short *)icmp_hdr,len));
        icmp_hdr->checksum=htons(csumicmp);
       // memcpy(&(icmp_hdr->checksum),(&csumicmp),2);
        //icmp_hdr->checksum= (icmpChecksum((unsigned short *)icmp_hdr,(len-14-20)));
    }
    if(pkt_type==2){
        //change the src ip and dst ipaddr
        //char* srcip;
        //srcip=(char*)malloc(32);
        //u_char *timeExceedePacket =(char *)malloc(14+20+8+20+8+48);
        //copy the mac header
        memcpy(timeExceedePacket,(char*)eth_hdr,14);
        //copy original IP header after icmp
        memcpy(timeExceedePacket+14+20+8,ip_hdr,len-14);
       //copy data packet
        //memcpy(timeExceedePacket+62,(char *)(pkt_ptr+14+20+8),64);
        struct in_addr inp;
        inp=ip_hdr->ip_src;
        ip_hdr->ip_src=ip_hdr->ip_dst;
        ip_hdr->ip_dst=inp;
        ip_hdr->ip_len=htons(112);
        ///change the icmp code and type for reply
        printf("Changing icmp Header\n");
        struct icmphdr *icmp_hdr = (struct icmphdr *)(pkt_ptr+14+20);
        struct icmphdr *icmp_hdr_new  =(struct icmphdr *)(timeExceedePacket+14+20);
        //icmp_hdr_new->type=11; --Time exceeded
          icmp_hdr_new->type=11;  
        icmp_hdr_new->code=0;
        //printf("TYPE: %d\n",icmp_hdr->type);
        //printf("Code: %d\n",icmp_hdr->code);
        //printf("Checksum: %x\n",ntohs(icmp_hdr->checksum));
        icmp_hdr_new->checksum=0; 
        //memcpy(timeExceedePacket+14+20,icmp_hdr,8);
        unsigned short csumicmp= htons(icmpChecksum((unsigned short *)(timeExceedePacket+14+20),92));
        //struct icmphdr *icmp_hdr_new  =((struct icmphdr *)timeExceedePacket+14+20;
        icmp_hdr_new ->checksum=htons(csumicmp);
        //printf("-------------------CheckSum is: %02x\t-----------------\n",csumicmp);
        //copy icmp
        //memcpy(timeExceedePacket+14+20,icmp_hdr,8);
       // memcpy(&(icmp_hdr->checksum),(&csumicmp),2);
        //icmp_hdr->checksum= (icmpChecksum((unsigned short *)icmp_hdr,(len-14-20)));
    }

    //Change the ttl and checksum
    ip_hdr->ip_ttl-=1;
    if(ip_hdr->ip_ttl==0){
        ip_hdr->ip_ttl=64;
    }
    ip_hdr->ip_sum = (htons)(ip_checksum(ip_hdr));
    if(pkt_type==2){
        memcpy(timeExceedePacket+14,ip_hdr,20);

        return timeExceedePacket;
    }

    //printf("end of modify packet\n");

    return pkt_ptr;
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

uint8_t *parse_ether_address(char *ether_addr_str)
{   //printf("parse ether address\n");
    int i =-1,c,j=0; 
    char ch;
    uint8_t num=0, *ether_addr = malloc(sizeof(int)*6);
    do
    {   i++;    
        ch = ether_addr_str[i];
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

    /*printf("MAC- ");
    for(i=0;i<6;i++)
        printf("%x:",ether_addr[i]);
    printf("\n");
    */

    return ether_addr;
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

void printIcmp(const char *packet, int len){


    struct icmphdr *icmp_hdr = (struct icmphdr *) (struct icmp *)(packet+14+20);
    printf("TYPE: %d\n",icmp_hdr->type);
    printf("Code: %d\n",icmp_hdr->code);
    printf("Checksum: %x\n",ntohs(icmp_hdr->checksum));
    unsigned short id, seq;
    memcpy(&id,(packet+34+4),2);
    memcpy(&seq,packet+34+4+2,2);
    printf("id : %d\t seq: %d\t",id,seq);
   // printf("Identifier: %d\n",ntohl(icmp_hdr->identifier));
    //printf("Sequence: %d\n",ntohl(icmp_hdr->sequence));
    //printf("Data: %s\n",ntohl(icmp_hdr->data)); 
}

unsigned short icmpChecksum(unsigned short *buffer, int length)
{
    unsigned long sum;  
    //char *buffer =packet+14+20;
    // initialize sum to zero and loop until length (in words) is 0 

    for (sum=0; length>1; length-=2) // sizeof() returns number of bytes, we're interested in number of words 
        sum += *buffer++;   // add 1 word of buffer to sum and proceed to the next 

    // we may have an extra byte 
    if (length==1)
        sum += (char)*buffer;

    sum = (sum >> 16) + (sum & 0xFFFF);  // add high 16 to low 16 
    sum += (sum >> 16);          // add carry 
    return ~sum;
}

