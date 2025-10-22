#include "Detector.h"
#include <iostream>

void Detector::analyze(const PacketInfo& packet) {

	if (packet.srcIp.empty()) return;

    std::cout << "[+] Packet "
        << packet.srcIp << " ¡æ " << packet.dstIp
        << " proto=" << packet.protocol
        << " len=" << packet.rawLen << std::endl;
}