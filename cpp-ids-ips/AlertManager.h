#pragma once
#include <string>
#include "Logger.h"

class AlertManager {
public:
	void sendAlert(const std::string& msg);
};
