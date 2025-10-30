#include "Capture.h"
#include "Parser.h"
#include "RuleEngine.h"
#include "AlertManager.h"
#include "Logger.h"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "사용법: " << argv[0] << " <네트워크 인터페이스 이름>\n";
        std::cerr << "예시: " << argv[0] << " eth0\n";
        return 1;
    }

    std::string iface = argv[1];
    Logger::info("🚀 Simple IDS Starting...");
    Logger::info("📡 Listening on interface: " + iface);

    AlertManager alertManager;
    RuleEngine ruleEngine(alertManager);

    Capture capture;
    capture.setPacketHandler([&](const u_char* data, int len) {
        auto pkt = Parser::parse(data, len);
        if (!pkt.srcIP.empty()) ruleEngine.inspect(pkt);
        });

    capture.start(iface);
    return 0;
}
