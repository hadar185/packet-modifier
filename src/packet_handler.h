#pragma once

#include "rule.h"
#include "packet.h"

bool is_match(Packet *packet, Rule *rule);
Rule *get_matching_rule(Packet *packet, Rule *rules, int rule_count);
unsigned int handle_packet(Packet *packet, Rule *matched_rule);