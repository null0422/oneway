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
	u_char arp_dip[4]; /*target ip address*/
};

int main(int argc, char *argv[])
{
	pcap_t *handle;			/*session handle*/
	char *dev;			/*The device to sniff on*/
	char errbuf[PCAP_ERRBUF_SIZE];	/*Error string*/
	struct bpf_program fp;		/*The compiled filter*/
	char filter_exp[] = "port 80";	/*The filter expression*/
	bpf_u_int32 mask;		/*Our netmask*/
	bpf_u_int32 net;		/*Our IP*/
	struct pcap_pkthdr *header;	/*The header that pcap gives us*/
	int success;		/*The actual success*/

	struct sniff_arp arp;

	const u_char *pkt_data;
	int cnt=0;
	int pcnt=0;
	int idx,x,y;
	
	struct ip *ip_hdr;
	struct tcphdr *tcph;

	
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

	sscnaf(argv[2], "%d.%d.%d.%d", &arp.arp_dip[0], &arp.arp_dip[1], &arp.arp_dip[2], &arp.arp_dip[3]);
	char *NIC = argv[1];

	FILE *fp_ip;
	char i_buff[256];
	fp_ip = popen("ifconfig eth0 | grep inet", "r");
	fgets(i_buff, 255, fp_ip);
	pclose(fp_ip);
	sscnaf(fp_ip, "%d.%d.%d.%d", &arp.arp_sip[0], &arp.arp_sip[1], &arp.arp_sip[2], &arp.arp_sip[3]);

	FILE *fp_mac;
	char m_buff[256];
	fp_mac = popen("ifconfig eth0 | grep ether", "r");
	fgets(m_buff, 255, fp_mac);
	pclose(fp_mac);
	sscnaf(fp_mac, "%x:%x:%x:%x:%x:%x", &arp.eth_smac[0], &arp.eth_smac[1], &arp.eth_smac[2], &arp.eth_smac[3], &arp.eth_smac[4], &arp.eth_smac[5]);

	arp.eth_dmac[0] = 0xFF;
	arp.eth_dmac[1] = 0xFF;
	arp.eth_dmac[2] = 0xFF;
	arp.eth_dmac[3] = 0xFF;
	arp.eth_dmac[4] = 0xFF;
	arp.eth_dmac[5] = 0xFF;

	arp.eth_type = 0x0806;
	arp.arp_htype = htons(1);
	arp.arp_p = 0x0800;
	arp.arp_hsize = 0x06;
	arp.arp_psize = 0x04;
	arp.arp_opcode = 0x0001;
	memcpy(arp.arp_smac,arp.eth_smac,sizeof(arp.eth_smac));
	memcpy(arp.arp_dmac,arp.eth_dmac,sizeof(arp.eth_dmac));

	pcap_sendpacket(handle, (void*)arp, sizeof(arp));
		
	/*Grab a success*/

/*
	if(success = pcap_next_ex(handle, &header, &pkt_data)>=0)
	{
		
		

		
		int leng = header->len;
		for (idx = 0; idx < leng; idx++) {
			if(*(pkt_data + idx) < 16)
				printf("0%x ", (*(pkt_data + idx) & 0xff));
			else
				printf("%x ", (*(pkt_data + idx) & 0xff));
			if(idx%16==15)
				printf("\n");
			else if(idx%16==7)
				printf(" ");
			
		}
		printf("\nDMac address : ");
		for(idx=0; idx<6; idx++)
			printf("%x ",(*(pkt_data + idx) & 0xff));
		printf("\nSMAC address : ");
		for(idx=6; idx<12; idx++)
			printf("%x ",(*(pkt_data + idx) & 0xff));

		struct ether_header *ep;
		unsigned short ether_type;

		ep = (struct ether_header *)pkt_data;
		//ether_type = ntoh(ep->ether_type);
			int ip_hdr_len = ip_hdr->ip_hl * 4;

		ip_hdr = (pkt_data + sizeof(struct ether_header));
		tcph = (pkt_data + sizeof(struct ether_header) + ip_hdr_len);

		struct in_addr src_ip = ip_hdr->ip_src;
		struct in_addr dst_ip = ip_hdr->ip_dst;

		char src_ip_str[25];
		char dst_ip_str[25];
		inet_ntop(AF_INET, &src_ip, src_ip_str, 24);
		inet_ntop(AF_INET, &dst_ip, dst_ip_str, 24);

		printf("\nS-IP: %s ",&(src_ip_str));
		printf("\nD-IP : %s ",&(dst_ip_str));

		printf("\nS-Port : %d", ntohs(tcph->th_sport));
		printf("\nD-Port : %d", ntohs(tcph->th_dport));
		printf("\n ");
		
		int tcp_hdr_len = tcph->th_off * 4;
		int offset = sizeof(struct ether_header) + ip_hdr_len + tcp_hdr_len;

		for(idx=offset; idx<=header->len; idx++)
			printf("%c", *(pkt_data + idx));		
		
		
		printf("\n\n\n\n");


	}

	pcap_close(handle);
	*/
	
	return(0);
}		
	
	
	
