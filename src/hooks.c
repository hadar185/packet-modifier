#include "hooks.h"

unsigned int packet_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct nf_hook_params *params = (struct nf_hook_params *)priv;
    Packet packet = to_packet(skb);
    Rule *matched_rule;

    if (packet.ip_header) {
        matched_rule = get_matching_rule(&packet, params->rules, params->rule_count);
        if (matched_rule) {
            print_packet(&packet, KERN_INFO "Packet %d:%d to %d:%d matched a rule");
            return handle_packet(&packet, matched_rule);
        }
    }

    return NF_ACCEPT;
}

Rule post_routing_rules[1] = {
    {
        {
            {}, 
            {ntohl(0xC0A81101), htons(8000)}
        },
        {
            1, 
            {
                {ntohl(0xC0A81180)},
                {ntohl(0xC0A81101), htons(8080)}
            }
        }
    }
};
Rule pre_routing_rules[1] = {
    {
        {
            {ntohl(0xC0A81101), htons(8080)}, 
            {}
        }, 
        {
            1, 
            {
                {ntohl(0xC0A81101), htons(8000)},
                {ntohl(0xC0A80581)}
            }
        }
    }
};

const struct nf_hook_ops nf_ops[2] = {
    {
        .hook = packet_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_NAT_DST,
        .priv = &(struct nf_hook_params){
            .rules = pre_routing_rules,
            .rule_count = ARRAY_SIZE(pre_routing_rules)
        }
    },
    {
        .hook = packet_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_NAT_SRC,
        .priv = &(struct nf_hook_params){
            .rules = post_routing_rules,
            .rule_count = ARRAY_SIZE(post_routing_rules)
        }
    }
};