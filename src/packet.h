#pragma once

#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

union layer4
{
    struct tcphdr *tcp_header;
};

struct packet {
    struct iphdr *ip_header;
    union layer4 layer4;
};

struct packet to_packet(struct sk_buff *skb);
void print_packet(struct packet *packet);
void recalculate_checksum(struct packet *packet);