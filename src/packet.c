#include "packet.h"


struct packet to_packet(struct sk_buff *skb) {
    struct packet packet = {};

    if (!skb) {
        return packet;
    }

    packet.ip_header = ip_hdr(skb);
    if (!packet.ip_header) {
        return packet;
    }
    
    switch (packet.ip_header->protocol)
    {
        case IPPROTO_TCP:
            packet.layer4.tcp_header = tcp_hdr(skb);
            break;
        
        default:
            break;
    }
    return packet;
}

void recalculate_checksum(struct packet *packet) {
    packet->ip_header->check = 0;
    packet->ip_header->check = ip_fast_csum((unsigned char *)packet->ip_header, packet->ip_header->ihl);
    switch (packet->ip_header->protocol)
    {
        case IPPROTO_TCP:
            packet->layer4.tcp_header->check = 0;
            packet->layer4.tcp_header->check = csum_tcpudp_magic(
                packet->ip_header->saddr, packet->ip_header->daddr, 
                ntohs(packet->ip_header->tot_len) - (packet->ip_header->ihl << 2),
                IPPROTO_TCP, csum_partial((unsigned char *)packet->layer4.tcp_header,
                ntohs(packet->ip_header->tot_len) - (packet->ip_header->ihl << 2),0)
            );
            break;
        default:
            break;
    }
}

void print_packet(struct packet *packet) {
    printk(KERN_INFO "Packet %d:%d to %d:%d matched a rule",
        packet->ip_header->saddr,
        packet->layer4.tcp_header->source,
        packet->ip_header->daddr,
        packet->layer4.tcp_header->dest
    );
}
