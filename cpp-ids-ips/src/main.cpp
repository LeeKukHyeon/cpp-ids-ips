#include <iostream>
#include <string>
#include <thread>
#include <csignal>
#include <atomic>

#include "rules/RuleLoader.h"
#include "flow/FlowDetector.h"
#include "nfqueue/NFQueueHandler.h"
#include "logger/AsyncLogger.h"

std::atomic<bool> g_stop{ false };
NFQueueHandler* g_nfq = nullptr;
AsyncLogger* g_logger = nullptr;

void signal_handler(int signum) {
    std::cerr << "[*] Caught signal " << signum << ", stopping...\n";
    g_stop = true;
    if (g_nfq) g_nfq->stop();
    if (g_logger) g_logger->stop();
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [-i interface] [-q queue_num] [-r rules_file] [-l log_file] "
        << "[-t flow_threshold] [-w window_seconds]\n\n"
        << "Defaults:\n"
        << "  interface: eth0\n"
        << "  queue_num: 1\n"
        << "  rules_file: rules/example.rules\n"
        << "  log_file: logs/ids_alert.jsonl\n"
        << "  flow_threshold: 100\n"
        << "  window_seconds: 10\n";
}

int main(int argc, char** argv) {
    std::string iface = "eth0";
    int queue_num = 1;
    std::string rulesFile = "rules/example.rules";
    std::string logFile = "logs/ids_alert.jsonl";
    int flow_threshold = 100;
    int window_seconds = 10;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "-i" && i + 1 < argc) { iface = argv[++i]; }
        else if (a == "-q" && i + 1 < argc) { queue_num = std::stoi(argv[++i]); }
        else if (a == "-r" && i + 1 < argc) { rulesFile = argv[++i]; }
        else if (a == "-l" && i + 1 < argc) { logFile = argv[++i]; }
        else if (a == "-t" && i + 1 < argc) { flow_threshold = std::stoi(argv[++i]); }
        else if (a == "-w" && i + 1 < argc) { window_seconds = std::stoi(argv[++i]); }
        else if (a == "-h" || a == "--help") { print_usage(argv[0]); return 0; }
        else { std::cerr << "Unknown arg: " << a << "\n"; print_usage(argv[0]); return 1; }
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::cout << "[*] Secui-style IPS PoC (high-perf)\n";
    std::cout << "    interface: " << iface << "\n";
    std::cout << "    queue_num: " << queue_num << "\n";
    std::cout << "    rules_file: " << rulesFile << "\n";
    std::cout << "    log_file: " << logFile << "\n";
    std::cout << "    flow_threshold: " << flow_threshold << " per " << window_seconds << "s\n";

    RuleLoader loader;
    std::string err;
    if (!loader.loadRules(rulesFile, err)) {
        std::cerr << "Failed to load rules: " << err << std::endl;
        return 1;
    }
    std::cout << "[*] Loaded " << loader.getRules().size() << " rules\n";

    AsyncLogger logger(logFile);
    g_logger = &logger;

    FlowDetector flow(flow_threshold, window_seconds);

    NFQueueHandler nfq(queue_num, &loader, &flow, &logger, iface);
    g_nfq = &nfq;

    std::thread t([&]() {
        if (!nfq.start()) {
            std::cerr << "NFQ start failed\n";
            g_stop = true;
        }
        });

    while (!g_stop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    nfq.stop();
    logger.stop();

    if (t.joinable()) t.join();

    std::cout << "[*] Exited cleanly\n";
    return 0;
}
