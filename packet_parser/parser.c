#include<pcap.h>
#include<stdio.h>

#define ETHER_ADDR_LEN 6

struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};


int main(int argc,char * argv[],char * env[]){
	pcap_t * handle;
	char errbuf[PCAP_ERRBUF_SIZE]={};
	char * dev;
	struct bpf_program fp;
	char filter_exp[] = "port 23";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char * packet;

	dev = "ens33";

	if(pcap_lookupnet(dev,&net,&mask,errbuf) == -1){
		printf("pcap_lookupnet error");
	}

	handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle==NULL){
		printf("pcap_open_live error\n%s\n",errbuf);
		return(2);
	}
	if(pcap_compile(handle,&fp,filter_exp,0,net)==-1){
		printf("pcap_compile error\n%s\n",pcap_geterr(handle));
		return(2);
	}
	if(pcap_setfilter(handle,&fp)==-1){
		printf("setfilter error\n");
		return(2);
	}
	packet = pcap_next(handle,&header);

	printf("Jacked a packet with length of [%d]\n",header.len);
	pcap_close(handle);
	return(0);
}
