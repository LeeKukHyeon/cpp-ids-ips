#include "Parser.h"
#include <netinet/ether.h>
#include <cstring>

PacketInfo Parser::parse(const u_char* data, int len) {
    PacketInfo pkt;

    if (len < sizeof(ether_header)) return pkt;

    const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(data);
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return pkt;

    const struct ip* iphdr = reinterpret_cast<const struct ip*>(data + sizeof(struct ether_header));
    pkt.srcIP = inet_ntoa(iphdr->ip_src);
    pkt.dstIP = inet_ntoa(iphdr->ip_dst);
    pkt.protocol = iphdr->ip_p;

    int ip_header_len = iphdr->ip_hl * 4;
    const u_char* transport = data + sizeof(struct ether_header) + ip_header_len;

    if (pkt.protocol == IPPROTO_TCP && len >= sizeof(struct tcphdr)) {
        const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(transport);
        pkt.srcPort = ntohs(tcp->th_sport);
        pkt.dstPort = ntohs(tcp->th_dport);
    }
    else if (pkt.protocol == IPPROTO_UDP && len >= sizeof(struct udphdr)) {
        const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(transport);
        pkt.srcPort = ntohs(udp->uh_sport);
        pkt.dstPort = ntohs(udp->uh_dport);
    }

    return pkt;
}
