#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
	usage();
	return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
	fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
	return -1;
	}

	unsigned char data[16];
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
    
		
		if(packet[12]==0x08 && packet[13]==0x00 && packet[23]==0x06){
			unsigned char sport[2], dport[2];
			int i;
			for(i=0; i<2; i++){
				sport[i]= packet[34+i];
				dport[i]= packet[36+i];
			}
			uint16_t* src_port = (uint16_t*) sport;
			uint16_t* dest_port = (uint16_t*) dport;
			printf("src mac / dest mac = %x:%x:%x:%x:%x:%x / %x:%x:%x:%x:%x:%x\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11], packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
			printf("src ip / dest ip = %d.%d.%d.%d / %d.%d.%d.%d\n", packet[26], packet[27], packet[28], packet[29], packet[30], packet[31], packet[32], packet[33]);
    			printf("src port / dest port = %d / %d", ntohs(*src_port), ntohs(*dest_port));
		

			int ip_header = (int) (packet[14] & 0x0f) * 5;
			int tcp_header = (int)((packet[26 + ip_header] & 0xf0) >> 4) * 5;
			if(header -> len > tcp_header +32){
				int header_len = 14 + ip_header+ tcp_header;
				unsigned char data[32];
				int i;
				for(i = 0; i < 32 ; i++)
					data[i]=packet[header_len + i];
				printf("\ndata:");
				for(i = 0; i < 32; i++)
					printf("%x",data[i]);
			}
    			printf("\n______________\n");
    		}
  	}
  
	pcap_close(handle);
	return 0;
}
