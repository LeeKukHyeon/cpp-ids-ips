#include "FlowDetector.h"
#include <algorithm>

FlowDetector::FlowDetector(int threshold, int window_seconds)
    : threshold_(threshold), window_seconds_(std::max(1, window_seconds)) {
}

void FlowDetector::advanceToNow(Entry& e) {
    using namespace std::chrono;
    auto now = steady_clock::now();
    auto secs = duration_cast<seconds>(now - e.head_ts).count();
    if (secs <= 0) return;
    if (secs >= window_seconds_) {
        std::fill(e.buckets.begin(), e.buckets.end(), 0);
        e.head = 0;
        e.head_ts = now;
        e.total = 0;
        return;
    }
    for (int i = 0; i < secs; ++i) {
        e.head = (e.head + 1) % window_seconds_;
        e.total -= e.buckets[e.head];
        e.buckets[e.head] = 0;
    }
    e.head_ts += seconds(secs);
}

void FlowDetector::addPacket(const std::string& src_ip) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto& e = map_[src_ip];
    if (e.buckets.empty()) {
        e.buckets.assign(window_seconds_, 0);
        e.head = 0;
        e.head_ts = std::chrono::steady_clock::now();
        e.total = 0;
    }
    advanceToNow(e);
    e.buckets[e.head] += 1;
    e.total += 1;
}

bool FlowDetector::checkThreshold(const std::string& src_ip, FlowEvent& evt) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = map_.find(src_ip);
    if (it == map_.end()) return false;
    auto& e = it->second;
    advanceToNow(e);
    if (e.total >= threshold_) {
        evt.src_ip = src_ip;
        evt.count = e.total;
        evt.window_seconds = window_seconds_;
        evt.threshold = threshold_;
        evt.timestamp = std::chrono::system_clock::now();
        std::fill(e.buckets.begin(), e.buckets.end(), 0);
        e.total = 0;
        e.head_ts = std::chrono::steady_clock::now();
        e.head = 0;
        return true;
    }
    return false;
}

void FlowDetector::garbageCollect() {
    std::lock_guard<std::mutex> lk(mtx_);
    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> to_erase;
    for (auto& p : map_) {
        auto& e = p.second;
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - e.head_ts).count();
        if (age > window_seconds_ * 3) to_erase.push_back(p.first);
    }
    for (auto& k : to_erase) map_.erase(k);
}
