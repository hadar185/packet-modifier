#pragma once

#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "rule.h"


union layer4
{
    struct tcphdr *tcp_header;
};

typedef struct packet {
    struct iphdr *ip_header;
    union layer4 layer4;
} Packet;

Packet to_packet(struct sk_buff *skb);
void modify_ip_header(Packet *packet, Rule *matched_rule);
void modify_tcp_header(Packet *packet, Rule *matched_rule);
void modify_packet(Packet *packet, Rule *matched_rule);
void print_packet(Packet *packet, char *message_format);