all: sniffer  route_table  arp_table  pktinjection  ethrchanges icmpchanges iphdrchanges rip rip_send
	gcc -o router   sniffer.o  route_table.o  arp_table.o  pktinjection.o ethrchanges.o icmpchanges.o iphdrchanges.o rip.o rip_send.o router.c -lpcap -lpthread 

sniffer:
	gcc -c -g -fno-stack-protector sniffer.c

route_table:
	gcc -c -g -fno-stack-protector route_table.c

arp_table:	
	gcc -c -g -fno-stack-protector arp_table.c

pktinjection:
	gcc -c -g -fno-stack-protector pktinjection.c

ethrchanges:
	gcc -c -g -fno-stack-protector ethrchanges.c

iphdrchanges:
	gcc -c -g -fno-stack-protector iphdrchanges.c

icmpchanges:
	gcc -c -g -fno-stack-protector icmpchanges.c 

rip:
	gcc -c -g -fno-stack-protector rip.c

rip_send:
	gcc -c -g -fno-stack-protector rip_send.c
	
clean:  clean_obj
	rm -rf router 

clean_obj:
	rm -rf *.o
