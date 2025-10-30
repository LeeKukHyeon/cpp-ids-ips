#pragma once
#include "Parser.h"
#include "AlertManager.h"

class RuleEngine {
	AlertManager& alertMgr;
public:
	RuleEngine(AlertManager& am);
	void inspect(const PacketInfo& pkt);
};