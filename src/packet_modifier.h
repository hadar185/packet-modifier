#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <net/checksum.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HDR");
MODULE_DESCRIPTION("Modifies packets by given rules");
MODULE_VERSION("0.01");

struct rule post_routing_rules[] = {
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
struct rule pre_routing_rules[] = {
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

struct rule *is_match(struct rule* rules, int rule_count, struct packet *packet);
unsigned int filter_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
void modify_packet(struct rule *matched_rule, struct packet *packet);
int handle_packet(struct rule *matched_rule, struct packet *packet);

static int __init rootkit_init(void);
static void __exit rootkit_exit(void);