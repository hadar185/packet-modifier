#pragma once

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/in.h>

struct address {
    __be32 ip;
    __be16 port;
};

struct filter {
    struct address src;
    struct address dst;
    int protocol;
};

enum action_type {
    DROP = 0,
    MODIFY = 1,
};

struct action {
    enum action_type action_type;
    struct filter filter;
};

typedef const struct rule {
    struct filter filter;
    struct action action;
} Rule;

void print_rule(Rule *rule);
void print_rules(Rule *rules, int rule_count);