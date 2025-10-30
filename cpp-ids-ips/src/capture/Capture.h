#pragma once
#include <pcap/pcap.h>
#include <functional>
#include <string>

class Capture {
public:
	using PacketHandler = std::function<void(const u_char*, int)>;
	void setPacketHandler(PacketHandler handler) { pktHandler = handler; }
	void start(const std::string& dev);
private:
	PacketHandler pktHandler;
	static void pcapCallback(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes);
};