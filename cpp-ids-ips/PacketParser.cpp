#include "PacketParser.h"
#include <cstring>

#ifdef PLATFORM_LINUX
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#endif

PacketInfo PacketParser::parse(const unsigned char* data, size_t length) {

	PacketInfo info;
#ifdef PLATFORM_LINUX
	if (length < sizeof(struct ether_header)) return info;
	const struct ether_header* eth = reinterpret_cast << const struct ether_header* > (data);
	if (ntohs(eth->ether_type) != ETHERTYPE_IP) return info;

	const struct ip* iph = reinterpret_cast << const struct ip* > (data + sizeof(struct ether_header));
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &iph->ip_src, src, sizeof(src));
	inet_ntop(AF_INET, &iph->ip_dst, dst, sizeof(dst));

	info.srcIp = src;
	info.dstIp = dst;
	info.protocol = iph->ip_p;
#endif
	return info;
}