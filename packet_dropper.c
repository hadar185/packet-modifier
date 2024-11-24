#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HDR");
MODULE_DESCRIPTION("packet dropper");
MODULE_VERSION("0.01");

static struct nf_hook_ops nfho;

const char *ip_str = "192.168.17.1";

unsigned int filter_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    // struct in_addr ip_addr;
    
    if (!skb) {
        return NF_ACCEPT;
    }

    ip_header = ip_hdr(skb);
    if (!ip_header) {
        return NF_ACCEPT;
    }
    
    // if (in4_pton(ip_str, strlen(ip_str), (u8 *)&ip_addr, NULL, NULL) != 1) {
    //     printk(KERN_ERR "Invalid IP address\n");
    // }

    if (ip_header->daddr == htonl(0xc0a81101)) {
        printk(KERN_INFO "Dropping packet destined for 192.168.17.1\n");
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static int __init rootkit_init(void)
{
    memset(&nfho, 0, sizeof(struct nf_hook_ops));

    nfho.hook = filter_packet;
    nfho.pf = PF_INET;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = 0;

    if (nf_register_net_hook(&init_net, &nfho)) {
        printk(KERN_ERR "Failed to register Netfilter hook\n");
        return -1;
    }

    printk(KERN_INFO "rootkit: loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
