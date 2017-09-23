#include<pcap.h>
#include<stdio.h>
#include<libnet.h>

void handler(u_char * arg,const struct pcap_pkthdr * pkthdr,const u_char * packet)
{
	printf("I got packet!\n");
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
