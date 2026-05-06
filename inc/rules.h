#ifndef WINTPROXY_RULES_H
#define WINTPROXY_RULES_H

#include "config.h"
#include <stdint.h>

rule_action_t rules_match_ex(const rule_t *rules, size_t rule_count, rule_action_t default_action,
                             const char *process_name, uint32_t dst_ip,
                             uint16_t dst_port, uint8_t protocol, int *matched_rule_id);

#endif
