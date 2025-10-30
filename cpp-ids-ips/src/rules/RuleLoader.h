#include "RuleLoader.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <thread>
#include <vector>
#include <sys/inotify.h>
#include <unistd.h>
#include <chrono>

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

RuleLoader::RuleLoader(const std::string& path) : path_(path) {}

RuleLoader::~RuleLoader() {
    stopWatching();
}

RuleLoader::Rules RuleLoader::loadRules() {
    Rules rules;
    std::ifstream ifs(path_);
    if (!ifs) return rules;
    std::string line;
    while (std::getline(ifs, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> parts;
        std::istringstream ss(line);
        std::string tok;
        while (std::getline(ss, tok, ',')) parts.push_back(trim(tok));
        if (parts.size() < 5) continue;
        Rule r;
        r.proto = parts[0];
        r.direction = parts[1];
        r.field = parts[2];
        try { r.value = std::stoi(parts[3]); }
        catch (...) { continue; }
        r.message = parts[4];
        rules.push_back(r);
    }
    return rules;
}

void RuleLoader::startWatching(ChangeCallback cb) {
    if (running.load()) return;
    running.store(true);

    watcherThread = std::thread([this, cb]() {
        inotifyFd = inotify_init1(IN_NONBLOCK);
        if (inotifyFd < 0) {
            std::cerr << "inotify_init1 failed\n";
            running.store(false);
            return;
        }
        watchFd = inotify_add_watch(inotifyFd, path_.c_str(), IN_MODIFY | IN_CLOSE_WRITE);
        if (watchFd < 0) {
            std::cerr << "inotify_add_watch failed for " << path_ << "\n";
            close(inotifyFd);
            running.store(false);
            return;
        }

        // initial load
        cb(loadRules());

        const size_t bufLen = 1024 * (sizeof(struct inotify_event) + 16);
        std::vector<char> buf(bufLen);

        while (running.load()) {
            ssize_t len = read(inotifyFd, buf.data(), bufLen);
            if (len > 0) {
                size_t i = 0;
                while (i < (size_t)len) {
                    struct inotify_event* event = reinterpret_cast<struct inotify_event*>(&buf[i]);
                    if (event->mask & (IN_MODIFY | IN_CLOSE_WRITE)) {
                        cb(loadRules());
                    }
                    i += sizeof(struct inotify_event) + event->len;
                }
            }
            // sleep with small granularity so stopWatching() can react
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        // cleanup
        if (watchFd >= 0) inotify_rm_watch(inotifyFd, watchFd);
        if (inotifyFd >= 0) close(inotifyFd);
        watchFd = -1;
        inotifyFd = -1;
        });
}

void RuleLoader::stopWatching() {
    if (!running.load()) {
        // still ensure thread cleaned up if created
        if (watcherThread.joinable()) {
            watcherThread.join();
        }
        return;
    }

    running.store(false);

    // wait for thread to exit and join it
    if (watcherThread.joinable()) {
        watcherThread.join();
    }
}
