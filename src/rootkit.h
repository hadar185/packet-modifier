#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "hooks.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HDR");
MODULE_DESCRIPTION("Modifies packets by given rules");
MODULE_VERSION("0.01");

extern Rule pre_routing_rules[1];
extern Rule post_routing_rules[1];
extern const struct nf_hook_ops nf_ops[2];

static int __init rootkit_init(void);
static void __exit rootkit_exit(void);