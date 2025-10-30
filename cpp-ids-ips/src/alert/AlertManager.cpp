#include "AlertManager.h"
#include "../utils/Logger.h"
#include <chrono>
#include <iomanip>

AlertManager::AlertManager() {}
AlertManager::~AlertManager() {
	if (ofs.is_open()) ofs.close();
}

void AlertManager::sendLogFile(const std::string& path) {
	if (ofs.is_open()) ofs.close();
	ofs.open(path, std::ios::app);
	if (!ofs) {
		Logger::warn("Failed to open alert log file: " + path);
	}
	else {
		Logger::info("Alert log file: " + path);
	}
}

void AlertManager::sendAlert(const std::string& msg) {
	std::lock_guard<std::mutex> lk(mtx);
	Logger::warn("Alert : " + msg);
	if (ofs.is_open()) {
		auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
		ofs << "[" << std::put_time(std::localtime(&now), "%F %T") << "] ALERT: " << msg << std::endl;
		ofs.flush();
	}
}
