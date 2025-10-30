#include "RuleLoader.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <thread>
#include <vector>
#include <sys/inotify.h>
#include <unistd.h>

static std::string trim(const std::string& s) {
	size_t a = s.find_first_not_of(" \t\r\n");
	if (a == std::string::npos) return "";
	size_t b = s.find_last_not_of(" \t\r\n");
	return s.substr(a, b - a + 1);
}

RuleLoader::RuleLoader(const std::string& path) : path_(path) {}
RuleLoader::~RuleLoader() { stopWatching(); }

RuleLoader::Rules RuleLoader::loadRules() {
	Rules rules;
	std::ifstream ifs(path_);
	if (!ifs) return rules;
	std::string line;
	while (std::getline(ifs, line)) {
		line = trim(line);
		if (line.empty() || line[0] == '#') continue;
		std::vector<std::string> parts;
		std::istringstream ss(line);
		std::string tok;
		while (std::getline(ss, tok, ',')) parts.push_back(trim(tok));
		if (parts.size() < 5) continue;
		Rule r;
		r.proto = parts[0];
		r.direction = parts[1];
		r.field = parts[2];
		try { r.value = std::stoi(parts[3]); }
		catch (...) { continue; }

		r.message = parts[4];
		rules.push_back(r);
	}
	return rules;
}