#include "policy/rules.h"
#include "app/config.h"
#include "core/util.h"
#include <ctype.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

static void lowercase_ascii(char *s) {
    while (*s) {
        *s = (char)tolower((unsigned char)*s);
        s++;
    }
}

static int policy_rule_matches_process(const policy_rule_t *r, const char *process_name) {
    char name_lower[256];

    if (r->process_any) return 1;
    if (!process_name || !safe_str_copy(name_lower, sizeof(name_lower), process_name)) {
        return 0;
    }

    lowercase_ascii(name_lower);
    size_t nlen = strlen(name_lower);

    for (size_t i = 0; i < r->process_pattern_count; i++) {
        const process_pattern_t *p = &r->process_patterns[i];
        switch (p->type) {
        case RULE_PROCESS_ANY:
            return 1;
        case RULE_PROCESS_EXACT:
            if (strcmp(name_lower, p->text) == 0) return 1;
            break;
        case RULE_PROCESS_PREFIX:
            if (nlen >= p->len && strncmp(name_lower, p->text, p->len) == 0) return 1;
            break;
        case RULE_PROCESS_SUFFIX:
            if (nlen >= p->len && strcmp(name_lower + nlen - p->len, p->text) == 0) return 1;
            break;
        case RULE_PROCESS_CONTAINS:
            if (strstr(name_lower, p->text) != NULL) return 1;
            break;
        }
    }

    return 0;
}

static int policy_rule_matches_ip(const policy_rule_t *r, uint32_t ip) {
    uint32_t ip_host;

    if (r->ip_any) return 1;

    ip_host = ipv4_net_to_host(ip);
    for (size_t i = 0; i < r->ip_range_count; i++) {
        const ip_range_t *range = &r->ip_ranges[i];
        if (ip_host < range->start) return 0;
        if (ip_host <= range->end) return 1;
    }
    return 0;
}

static int policy_rule_matches_port(const policy_rule_t *r, uint16_t port) {
    if (r->port_any) return 1;

    for (size_t i = 0; i < r->port_range_count; i++) {
        const port_range_t *range = &r->port_ranges[i];
        if (port < range->start) return 0;
        if (port <= range->end) return 1;
    }
    return 0;
}

static uint8_t rule_protocol_number(const policy_rule_t *r) {
    if (r->protocol == RULE_PROTO_TCP) return 6;
    if (r->protocol == RULE_PROTO_UDP) return 17;
    return 0;
}

rule_decision_t policy_rules_match(const policy_rule_t *rules, size_t rule_count,
                                   rule_decision_t default_decision,
                                   const char *process_name, uint32_t dst_ip,
                                   uint16_t dst_port, uint8_t protocol,
                                   int *matched_rule_id) {
    if (matched_rule_id) *matched_rule_id = 0;

    for (size_t i = 0; i < rule_count; i++) {
        const policy_rule_t *r = &rules[i];
        uint8_t rule_proto;

        if (!r->enabled) continue;

        rule_proto = rule_protocol_number(r);
        if (rule_proto != 0 && rule_proto != protocol) continue;

        if (policy_rule_matches_process(r, process_name) &&
            policy_rule_matches_ip(r, dst_ip) &&
            policy_rule_matches_port(r, dst_port)) {
            if (matched_rule_id) *matched_rule_id = r->id;
            return r->decision;
        }
    }

    return default_decision;
}
