#pragma once
#include <netinet/in.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include "rules/RuleLoader.h"
#include "flow/FlowDetector.h"
#include "logger/AsyncLogger.h"

class NFQueueHandler {
public:
    NFQueueHandler(int qnum, RuleLoader* loader, FlowDetector* flow, AsyncLogger* logger, const std::string& iface);
    ~NFQueueHandler();

    bool start();
    void stop();

private:
    int queue_num;
    std::string iface;
    struct nfq_handle* h;
    struct nfq_q_handle* qh;
    int fd;
    bool running;

    RuleLoader* ruleLoader;
    FlowDetector* flowDetector;
    AsyncLogger* logger;

    static int nfCallback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
        struct nfq_data* nfa, void* data);
};
