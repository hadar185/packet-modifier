#include "rule.h"

void print_rule(Rule *rule) {
    printk(
        KERN_INFO "Rule: filter: %pI4:%u to %pI4:%u action: %pI4:%u to %pI4:%u",
        &rule->filter.src.ip,
        ntohs(rule->filter.src.port),
        &rule->filter.dst.ip,
        ntohs(rule->filter.dst.port),
        &rule->action.filter.src.ip,
        ntohs(rule->action.filter.src.port),
        &rule->action.filter.dst.ip,
        ntohs(rule->action.filter.dst.port)
    );
}

void print_rules(Rule *rules, int rule_count) {
    unsigned int i = 0;
    for (i = 0; i < rule_count; i++)
    {
        print_rule(&rules[i]);
    }
}