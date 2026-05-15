#ifndef WINTPROXY_POLICY_RULES_H
#define WINTPROXY_POLICY_RULES_H

#include "app/config.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

rule_decision_t policy_rules_match(const policy_rule_t *rules, size_t rule_count,
                                   rule_decision_t default_decision,
                                   const char *process_name, uint32_t dst_ip,
                                   uint16_t dst_port, uint8_t protocol,
                                   int *matched_rule_id);

#ifdef __cplusplus
}
#endif

#endif
