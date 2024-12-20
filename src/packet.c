#include "packet.h"


Packet to_packet(struct sk_buff *skb) {
    Packet packet = {};

    if (!skb) {
        return packet;
    }

    packet.ip_header = ip_hdr(skb);
    if (packet.ip_header) {
        switch (packet.ip_header->protocol)
        {
            case IPPROTO_TCP:
                packet.layer4.tcp_header = tcp_hdr(skb);
                break;
            
            default:
                break;
        }
    }
    return packet;
}

void modify_ip_header(Packet *packet, Rule *matched_rule) {
    if (matched_rule->action.filter.src.ip) {
        packet->ip_header->saddr = matched_rule->action.filter.src.ip;
    }
    if (matched_rule->action.filter.dst.ip) {
        packet->ip_header->daddr = matched_rule->action.filter.dst.ip;
    }
    packet->ip_header->check = 0;
    packet->ip_header->check = ip_fast_csum((unsigned char *)packet->ip_header, packet->ip_header->ihl);
}

void modify_tcp_header(Packet *packet, Rule *matched_rule) {
    if (matched_rule->action.filter.src.port) {
        packet->layer4.tcp_header->source = matched_rule->action.filter.src.port;
    }
    if (matched_rule->action.filter.dst.port) {
        packet->layer4.tcp_header->dest = matched_rule->action.filter.dst.port;
    }
    packet->layer4.tcp_header->check = 0;
    packet->layer4.tcp_header->check = csum_tcpudp_magic(
        packet->ip_header->saddr, packet->ip_header->daddr, 
        ntohs(packet->ip_header->tot_len) - (packet->ip_header->ihl << 2),
        IPPROTO_TCP, csum_partial((unsigned char *)packet->layer4.tcp_header,
        ntohs(packet->ip_header->tot_len) - (packet->ip_header->ihl << 2),0)
    );
}

void modify_packet(Packet *packet, Rule *matched_rule) {
    modify_ip_header(packet, matched_rule);
    switch (packet->ip_header->protocol)
    {
        case IPPROTO_TCP:
            modify_tcp_header(packet, matched_rule);
            break;
        default:
            break;
    }
}

void print_packet(Packet *packet, char *message_format) {
    printk(message_format,
        packet->ip_header->saddr,
        packet->layer4.tcp_header->source,
        packet->ip_header->daddr,
        packet->layer4.tcp_header->dest
    );
}
