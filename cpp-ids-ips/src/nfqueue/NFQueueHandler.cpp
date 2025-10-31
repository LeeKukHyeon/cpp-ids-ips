#include "NFQueueHandler.h"
#include <iostream>
#include <unistd.h>
#include <linux/netfilter_ipv4.h>
#include <cstring>
#include <ctime>
#include <nlohmann/json.hpp>
#include <thread>
#include <vector>

using json = nlohmann::json;

NFQueueHandler::NFQueueHandler(int qnum, RuleLoader* loader, FlowDetector* flow, AsyncLogger* logg, const std::string& nic)
    : queue_num(qnum), iface(nic), h(nullptr), qh(nullptr), fd(-1), running(false),
    ruleLoader(loader), flowDetector(flow), logger(logg) {
}

NFQueueHandler::~NFQueueHandler() { stop(); }

static int get_payload(struct nfq_data* tb, unsigned char** data) {
    return nfq_get_payload(tb, data);
}

int NFQueueHandler::nfCallback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
    struct nfq_data* nfa, void* data) {
    NFQueueHandler* self = reinterpret_cast<NFQueueHandler*>(data);
    unsigned char* pkt_data = nullptr;
    int pkt_len = get_payload(nfa, &pkt_data);
    if (pkt_len <= 0) {
        uint32_t id = 0;
        if (struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa)) id = ntohl(ph->packet_id);
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        return 0;
    }

    std::string src_ip;
    if (pkt_len >= 20) {
        char ipbuf[32];
        snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", pkt_data[12], pkt_data[13], pkt_data[14], pkt_data[15]);
        src_ip = ipbuf;
        if (self->flowDetector) self->flowDetector->addPacket(src_ip);
    }

    bool accept = true;
    std::shared_ptr<Rule> matchedRule = nullptr;

    if (self->ruleLoader) {
        // naive iteration - rules can be indexed by port/proto for performance
        for (auto& r : self->ruleLoader->getRules()) {
            if (!r->enabled) continue;
            if (r->match(pkt_data, pkt_len)) {
                matchedRule = r;
                if (r->action == "drop" || r->action == "block_temp") accept = false;
                break;
            }
        }
    }

    if (self->flowDetector) {
        FlowEvent evt;
        if (self->flowDetector->checkThreshold(src_ip, evt)) {
            accept = false;
            matchedRule = nullptr;
            json j;
            j["event"] = "flow_threshold_exceeded";
            j["src_ip"] = evt.src_ip;
            j["count"] = evt.count;
            j["window_seconds"] = evt.window_seconds;
            j["threshold"] = evt.threshold;
            j["action"] = "block_temp";
            j["timestamp"] = std::time(nullptr);
            if (self->logger) self->logger->log(j.dump());
        }
    }

    if (matchedRule) {
        json j;
        j["event"] = "rule_matched";
        j["sid"] = matchedRule->sid;
        j["msg"] = matchedRule->msg;
        j["action"] = matchedRule->action;
        j["src_ip"] = src_ip;
        j["timestamp"] = std::time(nullptr);
        if (self->logger) self->logger->log(j.dump());
    }

    uint32_t id = 0;
    if (struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa)) id = ntohl(ph->packet_id);
    nfq_set_verdict(qh, id, accept ? NF_ACCEPT : NF_DROP, 0, NULL);
    return 0;
}

bool NFQueueHandler::start() {
    h = nfq_open();
    if (!h) { std::cerr << "nfq_open failed\n"; return false; }
    if (nfq_unbind_pf(h, AF_INET) < 0) { /* ignore */ }
    if (nfq_bind_pf(h, AF_INET) < 0) { std::cerr << "nfq_bind_pf failed\n"; return false; }

    qh = nfq_create_queue(h, queue_num, &NFQueueHandler::nfCallback, this);
    if (!qh) { std::cerr << "nfq_create_queue failed\n"; return false; }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) { std::cerr << "can't set packet copy mode\n"; return false; }

    fd = nfq_fd(h);
    running = true;

    // programmatically insert iptables NFQUEUE rule for given iface
    std::string cmd = "iptables -I INPUT -i " + iface + " -j NFQUEUE --queue-num " + std::to_string(queue_num);
    std::cerr << "[NFQ] Running: " << cmd << std::endl;
    system(cmd.c_str());

    // worker threads: simple pool reading same fd (recv is thread-safe for this usage)
    const int WORKERS = 4;
    std::vector<std::thread> workers;
    for (int i = 0; i < WORKERS; ++i) {
        workers.emplace_back([this] {
            char buf[4096];
            while (running) {
                int rv = recv(fd, buf, sizeof(buf), 0);
                if (rv >= 0) nfq_handle_packet(h, buf, rv);
                else if (errno == ENOBUFS) {
                    // kernel dropped due to slow userland - continue
                    continue;
                }
                else {
                    break;
                }
            }
            });
    }

    // join workers (blocking)
    for (auto& t : workers) t.join();
    return true;
}

void NFQueueHandler::stop() {
    running = false;
    if (qh) { nfq_destroy_queue(qh); qh = nullptr; }
    if (h) { nfq_close(h); h = nullptr; }

    // remove iptables rule
    std::string cmd = "iptables -D INPUT -i " + iface + " -j NFQUEUE --queue-num " + std::to_string(queue_num);
    std::cerr << "[NFQ] Removing iptables rule: " << cmd << std::endl;
    system(cmd.c_str());
}
