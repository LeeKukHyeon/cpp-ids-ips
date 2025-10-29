#pragma once
#include <string>

class Logger {
public:
	static void info(const std::string& msg);
	static void warn(const std::string& msg);
private:
	static void print(const std::string& level, const std::string& msg);

};