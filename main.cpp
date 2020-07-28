#include<pcap.h>
#include<stdio.h>
#include<stdint.h>
#include<arpa/inet.h>
#include<string.h>
#include<cstdlib>
struct tcp_struct{
	u_char src_port[2];
	u_char dest_port[2];
	u_char seqack[8];
	u_char lenandres;
	u_char less[15];
};

struct ip_struct{
	u_char verihl;
	u_char trash[8];
	u_char ID;
	u_char header_checksum[2];
	u_char src_ip[4];
	u_char dest_ip[4];
};

struct eth_struct{
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char eth_type[2];
	ip_struct ip;
};

int main(int argc, char* argv[]){
	if(argc!=2){
		printf("usage : pcap-test <interface>");
		return -1;
	}
	
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
	while(true){
		int i, cnt=0;
		int ip_header, tcp_header;
		struct eth_struct eth;
		struct tcp_struct tcp;
		struct pcap_pkthdr* header;
		u_char data[16];
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) 
			continue;
		if (res == -1 || res == -2) 
			break;
		
		memcpy(&eth, packet, sizeof(struct eth_struct));
		if(eth.eth_type[0]==0x08 && eth.eth_type[1]==0x00 && eth.ip.ID==0x06){
			ip_header = (int) (eth.ip.verihl & 0x0f) *5;
			memcpy(&tcp, packet+14+ip_header, sizeof(struct tcp_struct));
			tcp_header = (int)((tcp.lenandres & 0xf0)>>4)*5;
			memcpy(data, packet + 14+ ip_header + tcp_header, sizeof(data));
	
			
			printf("<Ethernet Header>\nsrc mac: ");
			for (int i=0 ; i<sizeof(eth.src_addr) ; i++){
				printf("%02x",eth.src_addr[i]);
				if(i!=sizeof(eth.src_addr)-1)
					printf(":");
			}
			
			printf("\ndest mac: ");
			for (int i=0; i<sizeof(eth.dest_addr); i++){
				printf("%02x:",eth.dest_addr[i]);
				if(i!=sizeof(eth.dest_addr)-1)
					printf(":");
			}
			printf("\n");
		
			printf("<IP Header>\nsrc ip: ");
			for (int i=0 ; i<sizeof(eth.ip.src_ip); i++){
				printf("%d",eth.ip.src_ip[i]);
				if(i!=sizeof(eth.ip.src_ip)-1)
					printf(".");
			}
			printf("\ndest ip: ");
			for (int i=0; i<sizeof(eth.ip.dest_ip); i++ ){
				printf("%d",eth.ip.dest_ip[i]);
				if(i!=sizeof(eth.ip.dest_ip)-1)
					printf(".");
			}
			printf("\n");
		
			printf("<TCP Header>\nsrc port: ");
			printf("%d ",ntohs(*tcp.src_port));
			printf("\ndest port: ");
			printf("%d ",ntohs(*tcp.dest_port));
			printf("\n");
		
			printf("<Payload> (under 16 bytes)\n");
			if (data[0]==0)
				printf("No Data");
			else
				for(int i=0 ; i<sizeof(data); i++)
					printf("%02x", data[i]);
			printf("\n__________________\n");
			}
		
	}
	pcap_close(handle);
	return 0;	
}
