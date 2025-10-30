#pragma once
#include <string>
#include <fstream>
#include <mutex>

class AlertManager {
public:
	AlertManager();
	~AlertManager();

	void sendAlert(const std::string& msg);
	void sendLogFile(const std::string& path);
private:
	std::ofstream ofs;
	std::mutex mtx;
};
