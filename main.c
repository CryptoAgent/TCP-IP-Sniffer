#include "stdio.h"
#include "stdint.h"
#include <pcap.h>
#include <netinet/in.h>

struct ethernet{
	u_char dest_mac[6];
	u_char source_mac[6];
	u_short ether_type;
};
struct ip{
	u_char version_and_internet_hdr_len;
	u_char ip_type_of_service;
	u_short total_len;
	u_short ip_id;
	u_short fragment_offset;
	#define IP_RF 0x8000;
	#define IP_DF 0x4000;
	#define IP_MF 0x2000;
	u_char ttl;
	u_char proto;
	u_short checksum;
	struct in_addr scr_ip,dest_ip;
};

#define IP_HL(ip)		(((ip)->version_and_internet_hdr_len) & 0x0f)
#define IP_V(ip)		(((ip)->version_and_internet_hdr_len) >> 4)

struct tcp{
	u_short src_port;
	u_short dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	u_char th_offx2;
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short window;
	u_short sum;
	u_short urg_ptr;
};
void Single_packet(u_char * args,const struct pcap_pkthdr * header,const u_char * packet);
int main(int argc,char * argv[]){

	if(argc>2||argc<2){
		printf("Only one argument as a name of device needed\r\n");
		return 1;
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	const char * dev = argv[1];
	pcap_t * handle;
	handle = pcap_open_live(dev,65536,1,0,errbuf);
	if(handle==NULL){
		printf("Failure can't find device!\r\n");
		return 1;
	}
	pcap_loop(handle,-1,Single_packet,NULL);
	return 0;
}

void Single_packet(u_char * args,const struct pcap_pkthdr * header,const u_char * packet){

uint32_t ip_len;
uint32_t tcp_len;
const struct ethernet * ETH;
const struct ip * IP;
const struct tcp * TCP;
const char * payload;

ETH = (struct ethernet *)(packet);
IP = (struct ip*)(packet+14);//offset on 14 bytes(size of our ethernet frame)
ip_len = IP_HL(IP)*4;
TCP = (struct tcp *)(packet+14+ip_len);
tcp_len = TH_OFF(TCP)*4;
payload = (u_char *)(packet+14+ip_len+tcp_len);
printf("%s\r\n",payload);
}