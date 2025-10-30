#pragma once
#include <string>
#include <cstdint>


struct PacketInfo {
	std::string srcIP;
	std::string dstIP;
	uint16_t srcPort = 0;
	uint16_t dstPort = 0;
	uint8_t protocol = 0; // IPPROTO_TCP or IPPROTO_UDP
};


class Parser {
public:
	static PacketInfo parse(const u_char* data, int len);
};