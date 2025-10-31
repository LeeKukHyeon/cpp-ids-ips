#pragma once
#include <string>
#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>

class AsyncLogger {
public:
    AsyncLogger(const std::string& filename);
    ~AsyncLogger();

    void log(const std::string& jsonLine);
    void stop();

private:
    std::string logFile;
    std::queue<std::string> buffer;
    std::mutex mtx;
    std::condition_variable cv;
    std::thread worker;
    bool running;

    void process();
};
