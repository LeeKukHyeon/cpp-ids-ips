#pragma once
#include <string>

class PacketSniffer {

public:
	explicit PacketSniffer(const std::string& interface);
	void startCapture();

private:
	std::string interface_;
	int sockfd_;
	void setupSocket();

};