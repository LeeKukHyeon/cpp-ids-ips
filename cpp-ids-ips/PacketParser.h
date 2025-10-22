#pragma once
#include <string>

struct PacketInfo {

	std::string srcIp;
	std::string dstIp;
	int protocol = 0;
	int srcPort = 0;
	int dstPort = 0;
	size_t rawLen = 0;
};

class PacketParser {

public:
	PacketParser() = default;
	~PacketParser() = default;

	PacketInfo parse(const unsigned char* data, size_t length);
};