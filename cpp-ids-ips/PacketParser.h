#pragma once
#include "Packet.h"

class PacketParser {

public:
	PacketParser() = default;
	~PacketParser() = default;

	// raw ethernet frame -> Packet (fills tcp seq/flags when available)
	Packet parse(const unsigned char* data, size_t len);
};