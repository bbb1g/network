#include<pcap.h>
#include<iostream>
#include<libnet.h>

void handler(u_char * arg,const struct pcap_pkthdr * pkthdr,const u_char * packet)
{
	libnet_ethernet_hdr * eth = (libnet_ethernet_hdr *)packet;
	uint16_t eth_type = ((eth->ether_type & 0xff)<<8) + 
		                ((eth->ether_type & 0xff00)>>8);

	libnet_ipv4_hdr * ip = (libnet_ipv4_hdr *)(packet + sizeof(libnet_ethernet_hdr));
	libnet_tcp_hdr * tcp = (libnet_tcp_hdr *)((u_char *)ip+sizeof(libnet_ipv4_hdr));

	if(eth_type != 0x0800)return;

	puts("-----------------------------------");
	//ETHERNET HEADER PARSING
	puts("+ETHERNET HEADER+");
	printf("Ethernet src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth->ether_shost[0],eth->ether_shost[1],
			eth->ether_shost[2],eth->ether_shost[3],
			eth->ether_shost[4],eth->ether_shost[5]);
	printf("Ethernet dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth->ether_dhost[0],eth->ether_dhost[1],
			eth->ether_dhost[2],eth->ether_dhost[3],
			eth->ether_dhost[4],eth->ether_dhost[5]);
	printf("Ethernet Type : 0x%04x\n",eth_type);
	putchar(10);

	//IP HEADER PARSING
	puts("+IP HEADER+");
	printf("IP src : %s\n",inet_ntoa(ip->ip_src));
	printf("IP dst : %s\n",inet_ntoa(ip->ip_dst));

	//TCP PARSING
	puts("+TCP HEADER+");
	printf("PORT src : %5d\n",tcp->th_sport);
	printf("PORT dst : %5d\n",tcp->th_dport);
	puts("-----------------------------------");
	printf("\n\n");
}

int main(int argc,char * argv[],char * env[]){
	pcap_t * handle;
	char errbuf[PCAP_ERRBUF_SIZE]={};
	char * dev;
	int cnt;

	dev = "ens33";

	handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle==NULL){
		printf("pcap_open_live error\n%s\n",errbuf);
		return(2);
	}

	if (pcap_loop(handle,-1,handler,(u_char *)&cnt) == -1){
		printf("pcap_loop error!");
		return(2);
	}

	pcap_close(handle);

	return(0);
}
