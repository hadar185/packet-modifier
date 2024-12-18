#pragma once

#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "rule.h"


union layer4
{
    struct tcphdr *tcp_header;
};

struct packet {
    struct iphdr *ip_header;
    union layer4 layer4;
};

struct packet to_packet(struct sk_buff *skb);
void modify_ip_header(struct packet *packet, struct rule *matched_rule);
void modify_tcp_header(struct packet *packet, struct rule *matched_rule);
void modify_packet(struct packet *packet, struct rule *matched_rule);
void print_packet(struct packet *packet);