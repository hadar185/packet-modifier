#include "rule.h"

char *get_protocol_name(int protocol) {
    switch (protocol) {
        case IPPROTO_TCP:
            return "tcp";
        case IPPROTO_UDP:
            return "udp";
        case IPPROTO_ICMP:
            return "icmp";
        default:
            return "unknown";
    }
}

void print_rule(Rule *rule) {
    char *protocol_name = get_protocol_name(rule->filter.protocol);
    printk(
        KERN_INFO "Rule - Filter: %pI4:%u to %pI4:%u, Protocol: %s, Action: %pI4:%u to %pI4:%u",
        &rule->filter.src.ip,
        ntohs(rule->filter.src.port),
        &rule->filter.dst.ip,
        ntohs(rule->filter.dst.port),
        protocol_name,
        &rule->action.filter.src.ip,
        ntohs(rule->action.filter.src.port),
        &rule->action.filter.dst.ip,
        ntohs(rule->action.filter.dst.port)
    );
}

void print_rules(Rule *rules, int rule_count) {
    unsigned int i = 0;
    for (i = 0; i < rule_count; i++)
    {
        print_rule(&rules[i]);
    }
}