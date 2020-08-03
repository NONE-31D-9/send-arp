#include "send-arp.h"

unsigned char* getMyMac(unsigned char* interface){
    int fd;
    struct ifreq ifr;
    unsigned char* i_face = interface;
    unsigned char* macAddr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;

    strncpy((char*)ifr.ifr_name, (const char*)i_face, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    macAddr =  (unsigned char*) ifr.ifr_hwaddr.sa_data;

    return macAddr;
}

unsigned char* getYourMac(Ip yourIP, char* myMacAddr){
    // EthArpPacket packet;

	// packet.eth_.dmac_ = Mac(myMacAddr);
	// packet.eth_.smac_ = Mac("ff:ff:ff:ff:ff:ff");
	// packet.eth_.type_ = htons(EthHdr::Arp);

	// packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	// packet.arp_.pro_ = htons(EthHdr::Ip4);
	// packet.arp_.hln_ = Mac::SIZE;
	// packet.arp_.pln_ = Ip::SIZE;
	// packet.arp_.op_ = htons(ArpHdr::Request);
	// packet.arp_.smac_ = Mac(myMacAddr);
	// packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	// packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	// packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

	// int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	// if (res != 0) {
	// 	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	// }

    // EtherArpPacket resPacket = (EtherArpPacket)res;
    // printf("%s", resPacket.arp_.smac());

	// pcap_close(handle);
}