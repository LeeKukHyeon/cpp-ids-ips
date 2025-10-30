#pragma once
#include <string>

struct Rule {
	std::string proto;
	std::string direction;
	std::string field;
	int value = 0;
	std::string message;
};