#pragma once

#include "rule.h"
#include "packet.h"
#include "packet_handler.h"
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

struct nf_hook_params {
    Rule *rules;
    int rule_count;
};

unsigned int packet_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);