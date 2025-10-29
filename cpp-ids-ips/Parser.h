#pragma once
#ifdef _WIN32
// Windows 환경일 경우 — 빈 선언만 추가
// (리눅스용 코드가 컴파일되지 않도록 막음)
using u_char = unsigned char;
#else
// Linux / macOS 환경
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#endif
#include <string>

struct PacketInfo {
	std::string srcIP;
	std::string dstIP;
	uint16_t srcPort = 0;
	uint16_t dstPort = 0;
	uint8_t protocol = 0;
};

class Parser {
public:
	static PacketInfo parse(const u_char* data, int len);
};