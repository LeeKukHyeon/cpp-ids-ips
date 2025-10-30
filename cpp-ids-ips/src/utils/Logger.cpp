#include "Logger.h"
#include <iostream>
#include <chrono>
#include <iomanip>

void Logger::info(const std::string& msg) {
    print("INFO", msg);
}

void Logger::warn(const std::string& msg) {
    print("WARN", msg);
}

void Logger::print(const std::string& level, const std::string& msg) {
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::cout << "[" << std::put_time(std::localtime(&now), "%F %T") << "] "
        << "[" << level << "] " << msg << std::endl;
}
