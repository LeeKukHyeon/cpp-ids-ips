#include "AsyncLogger.h"
#include <fstream>

AsyncLogger::AsyncLogger(const std::string& filename) : logFile(filename), running(true) {
    worker = std::thread(&AsyncLogger::process, this);
}

AsyncLogger::~AsyncLogger() { stop(); }

void AsyncLogger::log(const std::string& jsonLine) {
    std::unique_lock<std::mutex> lk(mtx);
    buffer.push(jsonLine);
    cv.notify_one();
}

void AsyncLogger::stop() {
    if (!running) return;
    running = false;
    cv.notify_all();
    if (worker.joinable()) worker.join();
}

void AsyncLogger::process() {
    std::ofstream ofs(logFile, std::ios::app);
    while (running || !buffer.empty()) {
        std::unique_lock<std::mutex> lk(mtx);
        cv.wait(lk, [&] { return !running || !buffer.empty(); });
        while (!buffer.empty()) {
            ofs << buffer.front() << std::endl;
            buffer.pop();
        }
        ofs.flush();
    }
}
