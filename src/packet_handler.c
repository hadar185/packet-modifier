#include "packet_handler.h"


bool is_match(Packet *packet, Rule *rule) {
    if ((!rule->filter.src.ip || rule->filter.src.ip == packet->ip_header->saddr) &&
        (!rule->filter.dst.ip || rule->filter.dst.ip == packet->ip_header->daddr))
    {
        switch (packet->ip_header->protocol)
        {
            case IPPROTO_TCP:
                if ((!rule->filter.src.port || rule->filter.src.port == packet->layer4.tcp_header->source) &&
                    (!rule->filter.dst.port || rule->filter.dst.port == packet->layer4.tcp_header->dest)) 
                {
                    return true;
                }
                break;
            default:
                break;
        }
    }
    return false;
}

Rule *get_matching_rule(Packet *packet, Rule* rules, int rule_count) {
    unsigned int rule_index;
    for (rule_index = 0; rule_index < rule_count; rule_index++) {
        Rule *rule = &rules[rule_index];
        if (is_match(packet, rule)) {
            return rule;
        }
    }
    return NULL;
}

unsigned int handle_packet(Packet *packet, Rule *matched_rule) {
    switch (matched_rule->action.action_type)
    {
        case DROP:
            printk(KERN_INFO "Dropping packet\n");
            return NF_DROP;
        case MODIFY:
            printk(KERN_INFO "Modifying packet\n");
            modify_packet(packet, matched_rule);
            break;
        default:
            break;
    }
    return NF_ACCEPT;
}