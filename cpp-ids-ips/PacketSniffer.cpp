#include "PacketSniffer.h"
#include "PacketParser.h"
#include "Detector.h"
#include <iostream>
#include <cstring>

#ifdef PLATFORM_LINUX
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#elif defined(PLATFORM_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#endif


PacketSniffer::PacketSniffer(const std::string& interface)
	: interface_(interface), sockfd_(-1) {}

void PacketSniffer::setupSocket() {


#ifdef PLATFORM_LINUX
	sockfd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sockfd_ < 0) {
		perror("socket");
		exit(1);
	}

	struct ifreq ifr {};
	strncpy(ifr.ifr_name.interface_.c_str(), IFNAMSIZ);

	if (ioctl(sockfd_, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	struct sockaddr_ll sll {};

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifr.ifr_ifindex;

	if (bind(sockfd_, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
		perror("bind");
		exit(1);
	}

#elif defined(PLATFORM_WINDOWS)
	std::cout << << "[!] Raw socket capture is not supported on Windows without Npcap.\n";
	exit(1);
#endif
	std::cout << "[+] Listening on interface: " << interface_ << std::endl;


}

void PacketSniffer::startCapture() {
#ifdef PLATFORM_LINUX
	setupSocket();
	char buffer[2048];
	PacketParser parser;
	Detector detector;

	while (true) {
		ssize_t len = recvfrom(sockfd_, buffer, sizeof(buffer), 0, nullptr, nullptr);
		if (len <= 0) continue;

		auto packet = parser.parse(reinterpret_cast<unsigned char*>(buffer), len);
		detector.analyze(packet);
	}


#else
	std::cout << "[!] Packet capture is not available on this platform \n";
#endif
}
