#pragma once
#include <string>


struct Rule {
	std::string proto; // tcp|udp|any
	std::string direction; // dst|src|any
	std::string field; // port currently
	int value = 0;
	std::string message;
};