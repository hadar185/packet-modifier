#pragma once

#include <linux/init.h>
#include <linux/kernel.h>

struct address {
    int ip;
    int port;
};

struct filter {
    struct address src;
    struct address dst;
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

void print_rule(struct rule *rule);
void print_rules(struct rule *rules, int rule_count);