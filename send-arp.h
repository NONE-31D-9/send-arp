#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>

#include <cstdio>
#include <pcap.h>
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

// reference : http://www.drk.com.ar/code/get-mac-address-in-linux.php
unsigned char* getMyMac(unsigned char* interface);

unsigned char* getYourMac(Ip yourIP, char* myMacAddr);

void send_arp();