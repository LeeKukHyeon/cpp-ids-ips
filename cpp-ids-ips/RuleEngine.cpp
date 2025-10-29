#include "RuleEngine.h"

RuleEngine::RuleEngine(AlertManager& am) : alertMgr(am) {}

void RuleEngine::inspect(const PacketInfo& pkt) {
    if (pkt.dstPort == 22) {
        alertMgr.sendAlert("SSH access detected: " + pkt.srcIP + " ¡æ " + pkt.dstIP);
    }
    if (pkt.protocol == IPPROTO_TCP && pkt.dstPort == 80) {
        alertMgr.sendAlert("HTTP traffic detected: " + pkt.srcIP + " ¡æ " + pkt.dstIP);
    }
}
