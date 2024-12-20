#include "rule.h"

void print_rule(Rule *rule) {
    printk(
        KERN_INFO "Rule: filter: %d:%d to %d:%d action: %d:%d to %d:%d",
        rule->filter.src.ip,
        rule->filter.src.port,
        rule->filter.dst.ip,
        rule->filter.dst.port,
        rule->action.filter.src.ip,
        rule->action.filter.src.port,
        rule->action.filter.dst.ip,
        rule->action.filter.dst.port
    );
}

void print_rules(Rule *rules, int rule_count) {
    unsigned int i = 0;
    for (i = 0; i < rule_count; i++)
    {
        print_rule(&rules[i]);
    }
}