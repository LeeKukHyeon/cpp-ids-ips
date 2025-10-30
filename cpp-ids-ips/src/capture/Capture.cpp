#include "Capture.h"
#include "../utils/Logger.h"
#include <iostream>

void Capture::start(const std::string& dev) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev.c_str(), 65536, 1, 1000, errbuf);
	if (!handle) {
		Logger::warn(std::string("pcap_open_live_failed: ") + dev + ": " + errbuf);
		return;
	}

	Logger::info(std::string("Listening on interface: ") + dev);
	pcap_loop(handle, 0, pcapCallback, reinterpret_cast<u_char*>(this));
	pcap_close(handle);
}

void Capture::pcapCallback(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
	Capture* self = reinterpret_cast<Capture*>(user);
	if (self->pktHandler) self->pktHandler(bytes, h->len);
}