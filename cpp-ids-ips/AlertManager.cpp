#include "AlertManager.h"

void AlertManager::sendAlert(const std::string& msg) {
	Logger::warn("Alert:" + msg);
}