#include<pcap.h>
#include<iostream>
#include<libnet.h>

void handler(u_char * arg,const struct pcap_pkthdr * pkthdr,const u_char * packet)
{
	libnet_ethernet_hdr * eth = (libnet_ethernet_hdr *)packet;
	printf("Ethernet source mac      : %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth->ether_shost[0],eth->ether_shost[1],
			eth->ether_shost[2],eth->ether_shost[3],
			eth->ether_shost[4],eth->ether_shost[5]);
	printf("Ethernet destination mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth->ether_dhost[0],eth->ether_dhost[1],
			eth->ether_dhost[2],eth->ether_dhost[3],
			eth->ether_dhost[4],eth->ether_dhost[5]);
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
	return(0);
}
