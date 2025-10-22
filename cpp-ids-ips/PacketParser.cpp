#include "PacketParser.h"
#include <cstring>

#ifdef PLATFORM_LINUX
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#endif

Packet PacketParser::parse(const unsigned char* data, size_t len) {
    Packet pkt;
    pkt.ts = std::chrono::steady_clock::now();
    if (!data || len < 14) return pkt;

#ifdef PLATFORM_LINUX
    const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(data);
    uint16_t eth_type = ntohs(eth->ether_type);
    if (eth_type != ETHERTYPE_IP) return pkt;

    size_t offset = 14;
    if (len < offset + sizeof(struct ip)) return pkt;
    const struct ip* iph = reinterpret_cast<const struct ip*>(data + offset);
    char sbuf[INET_ADDRSTRLEN] = { 0 }, dbuf[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &iph->ip_src, sbuf, sizeof(sbuf));
    inet_ntop(AF_INET, &iph->ip_dst, dbuf, sizeof(dbuf));
    pkt.srcIp = sbuf;
    pkt.dstIp = dbuf;
    pkt.protocol = std::to_string(iph->ip_p); // simple numeric protocol in string

    size_t ipHeaderLen = iph->ip_hl * 4;
    offset += ipHeaderLen;
    if (len < offset) return pkt;

    if (iph->ip_p == IPPROTO_TCP) {
        if (len < offset + sizeof(struct tcphdr)) return pkt;
        const struct tcphdr* tcph = reinterpret_cast<const struct tcphdr*>(data + offset);
        pkt.srcPort = ntohs(tcph->source);
        pkt.dstPort = ntohs(tcph->dest);
        // seq/ack and flags
#ifdef __linux__
        pkt.seq = ntohl(tcph->seq);
        pkt.ack = ntohl(tcph->ack_seq);
        pkt.flags = tcph->th_flags;
#else
        // fallback generic (may vary by platform)
        pkt.seq = ntohl(tcph->seq);
        pkt.ack = ntohl(tcph->ack_seq);
        pkt.flags = 0;
#endif
        pkt.tcpHasSeq = true;
        size_t tcpHeaderLen = tcph->th_off * 4;
        offset += tcpHeaderLen;
        if (offset > len) offset = len;
        size_t payload_len = (offset <= len) ? (len - offset) : 0;
        if (payload_len) pkt.payload.assign(data + offset, data + offset + payload_len);
    }
    else if (iph->ip_p == IPPROTO_UDP) {
        if (len < offset + sizeof(struct udphdr)) return pkt;
        const struct udphdr* udph = reinterpret_cast<const struct udphdr*>(data + offset);
        pkt.srcPort = ntohs(udph->source);
        pkt.dstPort = ntohs(udph->dest);
        offset += sizeof(struct udphdr);
        if (offset > len) offset = len;
        size_t payload_len = (offset <= len) ? (len - offset) : 0;
        if (payload_len) pkt.payload.assign(data + offset, data + offset + payload_len);
    }
    else if (iph->ip_p == IPPROTO_ICMP) {
        pkt.protocol = "ICMP";
        if (len > offset) pkt.payload.assign(data + offset, data + len);
    }
    else {
        // other protocols ignored for PoC
    }
#endif

    return pkt;
}
