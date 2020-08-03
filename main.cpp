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
	if (argc != 2) {
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

	unsigned char* myMacAddr = getMyMac((unsigned char*)argv[1]);
    printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" \
    , myMacAddr[0], myMacAddr[1], myMacAddr[2], myMacAddr[3], myMacAddr[4], myMacAddr[5]);
	
	Ip your_IP = Ip(argv[2]);

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(myMacAddr);
	packet.eth_.smac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(myMacAddr);
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

    EtherArpPacket resPacket = (EtherArpPacket)res;
    printf("%s", resPacket.arp_.smac());

	pcap_close(handle);

}
