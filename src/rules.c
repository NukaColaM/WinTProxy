#include "rules.h"
#include "config.h"
#include "log.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

static int rules_match_process(const char *pattern, const char *process_name) {
    if (!pattern || !process_name) return 0;
    if (strcmp(pattern, "*") == 0 || _stricmp(pattern, "any") == 0) return 1;

    char pat_lower[256], name_lower[256];
    if (!safe_str_copy(pat_lower, sizeof(pat_lower), pattern) ||
        !safe_str_copy(name_lower, sizeof(name_lower), process_name)) {
        return 0;
    }
    _strlwr(pat_lower);
    _strlwr(name_lower);

    /* Handle comma/semicolon separated lists */
    char *ctx = NULL;
    char *token = strtok_s(pat_lower, ",;", &ctx);
    while (token) {
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') { *end = '\0'; end--; }

        int match = 0;
        size_t tlen = strlen(token);
        size_t nlen = strlen(name_lower);

        if (tlen == 0) {
            token = strtok_s(NULL, ",;", &ctx);
            continue;
        }

        if (strcmp(token, "*") == 0) {
            match = 1;
        } else if (token[0] == '*' && token[tlen - 1] == '*' && tlen > 2) {
            /* *substring* */
            char sub[256];
            if (tlen - 2 >= sizeof(sub)) return 0;
            memcpy(sub, token + 1, tlen - 2);
            sub[tlen - 2] = '\0';
            match = strstr(name_lower, sub) != NULL;
        } else if (token[0] == '*') {
            /* *suffix */
            const char *suffix = token + 1;
            size_t slen = strlen(suffix);
            if (nlen >= slen) match = strcmp(name_lower + nlen - slen, suffix) == 0;
        } else if (token[tlen - 1] == '*') {
            /* prefix* */
            match = strncmp(name_lower, token, tlen - 1) == 0;
        } else {
            match = strcmp(name_lower, token) == 0;
        }

        if (match) return 1;
        token = strtok_s(NULL, ",;", &ctx);
    }
    return 0;
}

static int rules_match_ip(const ip_range_t *ranges, uint32_t ip) {
    uint32_t ip_host = ipv4_net_to_host(ip);
    if (!ranges) return 1;
    for (const ip_range_t *r = ranges; r; r = r->next) {
        if (ip_host >= r->start && ip_host <= r->end) return 1;
    }
    return 0;
}

static int rules_match_port(const char *pattern, uint16_t port) {
    if (!pattern) return 0;
    if (strcmp(pattern, "*") == 0) return 1;

    char pat_copy[128];
    if (!safe_str_copy(pat_copy, sizeof(pat_copy), pattern)) return 0;

    char *ctx = NULL;
    char *token = strtok_s(pat_copy, ",;", &ctx);
    while (token) {
        while (*token == ' ') token++;

        char *dash = strchr(token, '-');
        if (dash) {
            *dash = '\0';
            uint16_t lo = (uint16_t)atoi(token);
            uint16_t hi = (uint16_t)atoi(dash + 1);
            if (port >= lo && port <= hi) return 1;
        } else {
            if (port == (uint16_t)atoi(token)) return 1;
        }

        token = strtok_s(NULL, ",;", &ctx);
    }
    return 0;
}

rule_action_t rules_match(const rule_t *rules, rule_action_t default_action,
                          const char *process_name, uint32_t dst_ip,
                          uint16_t dst_port, uint8_t protocol) {
    uint8_t rule_proto;

    for (const rule_t *r = rules; r; r = r->next) {
        if (!r->enabled) continue;

        /* Check protocol compatibility */
        if (r->protocol == RULE_PROTO_TCP) rule_proto = 6;
        else if (r->protocol == RULE_PROTO_UDP) rule_proto = 17;
        else rule_proto = 0;

        if (rule_proto != 0 && rule_proto != protocol) continue;

        if (rules_match_process(r->process, process_name) &&
            rules_match_ip(r->ip_ranges, dst_ip) &&
            rules_match_port(r->port, dst_port)) {
            LOG_TRACE("Rule #%d matched process=%s", r->id, r->process);
            return r->action;
        }
    }

    return default_action;
}
