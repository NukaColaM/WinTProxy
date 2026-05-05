#include "config.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "cJSON/cJSON.h"

void config_set_defaults(app_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    strcpy(cfg->proxy.address, "127.0.0.1");
    cfg->proxy.port = 7890;
    cfg->dns.enabled = 0;
    strcpy(cfg->dns.redirect_address, "127.0.0.1");
    cfg->dns.redirect_port = 1053;
    cfg->rules = NULL;
    cfg->default_action = RULE_ACTION_PROXY;
    cfg->log_level = LOG_INFO;
    cfg->bypass_private_ips = 0;
}

static rule_action_t parse_action(const char *s) {
    if (!s) return RULE_ACTION_PROXY;
    if (_stricmp(s, "direct") == 0) return RULE_ACTION_DIRECT;
    if (_stricmp(s, "block") == 0) return RULE_ACTION_BLOCK;
    return RULE_ACTION_PROXY;
}

static rule_protocol_t parse_protocol(const char *s) {
    if (!s) return RULE_PROTO_BOTH;
    if (_stricmp(s, "tcp") == 0) return RULE_PROTO_TCP;
    if (_stricmp(s, "udp") == 0) return RULE_PROTO_UDP;
    return RULE_PROTO_BOTH;
}

static ip_range_t *ip_ranges_compile(const char *pattern) {
    if (!pattern || strcmp(pattern, "*") == 0) return NULL;

    char pat_copy[256];
    strncpy(pat_copy, pattern, sizeof(pat_copy) - 1);
    pat_copy[sizeof(pat_copy) - 1] = '\0';

    ip_range_t *head = NULL, *tail = NULL;
    char *ctx = NULL;
    char *token = strtok_s(pat_copy, ";", &ctx);
    while (token) {
        while (*token == ' ') token++;

        uint32_t start, end;
        int valid = 1;

        char *dash = strchr(token, '-');
        if (dash && strchr(token, '.')) {
            *dash = '\0';
            struct in_addr sa, ea;
            if (inet_pton(AF_INET, token, &sa) == 1 &&
                inet_pton(AF_INET, dash + 1, &ea) == 1) {
                start = sa.s_addr;
                end = ea.s_addr;
            } else valid = 0;
            *dash = '-';
        } else if (strchr(token, '/')) {
            char *slash = strchr(token, '/');
            *slash = '\0';
            struct in_addr net;
            int prefix = atoi(slash + 1);
            if (inet_pton(AF_INET, token, &net) == 1 && prefix >= 0 && prefix <= 32) {
                uint32_t h_mask = (prefix == 0) ? 0 : (0xFFFFFFFF << (32 - prefix));
                uint32_t n_mask = htonl(h_mask);
                start = net.s_addr & n_mask;
                end = net.s_addr | ~n_mask;
            } else valid = 0;
            *slash = '/';
        } else if (strchr(token, '*')) {
            char *oct_ctx = NULL;
            char tok_copy[64];
            strncpy(tok_copy, token, sizeof(tok_copy) - 1);
            tok_copy[sizeof(tok_copy) - 1] = '\0';
            char start_str[16], end_str[16];
            uint8_t so[4] = {0,0,0,0}, eo[4] = {0,0,0,0};
            char *p = strtok_s(tok_copy, ".", &oct_ctx);
            for (int i = 0; i < 4 && p; i++) {
                if (strcmp(p, "*") == 0) { so[i] = 0;   eo[i] = 255; }
                else                     { so[i] = eo[i] = (uint8_t)atoi(p); }
                p = strtok_s(NULL, ".", &oct_ctx);
            }
            snprintf(start_str, sizeof(start_str), "%u.%u.%u.%u", so[0], so[1], so[2], so[3]);
            snprintf(end_str,   sizeof(end_str),   "%u.%u.%u.%u", eo[0], eo[1], eo[2], eo[3]);
            struct in_addr sa, ea;
            if (inet_pton(AF_INET, start_str, &sa) == 1 &&
                inet_pton(AF_INET, end_str,   &ea) == 1) {
                start = sa.s_addr;
                end = ea.s_addr;
            } else valid = 0;
        } else {
            struct in_addr exact;
            if (inet_pton(AF_INET, token, &exact) == 1) {
                start = end = exact.s_addr;
            } else valid = 0;
        }

        if (valid) {
            ip_range_t *node = (ip_range_t *)calloc(1, sizeof(ip_range_t));
            if (node) {
                node->start = start;
                node->end   = end;
                if (!head) { head = tail = node; }
                else       { tail->next = node; tail = node; }
            }
        }
        token = strtok_s(NULL, ";", &ctx);
    }
    return head;
}

static void ip_ranges_free(ip_range_t *ranges) {
    while (ranges) {
        ip_range_t *next = ranges->next;
        free(ranges);
        ranges = next;
    }
}

static void resolve_ip(const char *addr_str, uint32_t *out_ip) {
    struct in_addr in;
    if (inet_pton(AF_INET, addr_str, &in) == 1) {
        *out_ip = in.s_addr;
    } else {
        inet_pton(AF_INET, "127.0.0.1", &in);
        *out_ip = in.s_addr;
    }
}

error_t config_load(app_config_t *cfg, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERROR("Cannot open config file: %s", path);
        return ERR_GENERIC;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = (char *)malloc(len + 1);
    if (!buf) { fclose(f); return ERR_MEMORY; }
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        LOG_ERROR("Failed to parse config JSON: %s", cJSON_GetErrorPtr());
        return ERR_GENERIC;
    }

    cJSON *proxy = cJSON_GetObjectItemCaseSensitive(root, "proxy");
    if (proxy) {
        cJSON *addr = cJSON_GetObjectItemCaseSensitive(proxy, "address");
        cJSON *port = cJSON_GetObjectItemCaseSensitive(proxy, "port");
        if (cJSON_IsString(addr)) strncpy(cfg->proxy.address, addr->valuestring, sizeof(cfg->proxy.address) - 1);
        if (cJSON_IsNumber(port)) cfg->proxy.port = (uint16_t)port->valueint;
    }

    cJSON *dns = cJSON_GetObjectItemCaseSensitive(root, "dns");
    if (dns) {
        cJSON *enabled = cJSON_GetObjectItemCaseSensitive(dns, "enabled");
        cJSON *addr = cJSON_GetObjectItemCaseSensitive(dns, "redirect_address");
        cJSON *port = cJSON_GetObjectItemCaseSensitive(dns, "redirect_port");
        if (cJSON_IsBool(enabled)) cfg->dns.enabled = cJSON_IsTrue(enabled);
        if (cJSON_IsString(addr)) strncpy(cfg->dns.redirect_address, addr->valuestring, sizeof(cfg->dns.redirect_address) - 1);
        if (cJSON_IsNumber(port)) cfg->dns.redirect_port = (uint16_t)port->valueint;
    }

    cJSON *def_action = cJSON_GetObjectItemCaseSensitive(root, "default_action");
    if (cJSON_IsString(def_action)) cfg->default_action = parse_action(def_action->valuestring);

    cJSON *log_lvl = cJSON_GetObjectItemCaseSensitive(root, "log_level");
    if (cJSON_IsString(log_lvl)) cfg->log_level = log_level_from_string(log_lvl->valuestring);

    cJSON *log_file = cJSON_GetObjectItemCaseSensitive(root, "log_file");
    if (cJSON_IsString(log_file)) strncpy(cfg->log_file, log_file->valuestring, sizeof(cfg->log_file) - 1);

    cJSON *bypass_priv = cJSON_GetObjectItemCaseSensitive(root, "bypass_private_ips");
    if (cJSON_IsBool(bypass_priv)) cfg->bypass_private_ips = cJSON_IsTrue(bypass_priv);

    cJSON *rules = cJSON_GetObjectItemCaseSensitive(root, "rules");
    if (cJSON_IsArray(rules)) {
        int count = cJSON_GetArraySize(rules);
        rule_t *tail = NULL;
        for (int i = 0; i < count; i++) {
            cJSON *item = cJSON_GetArrayItem(rules, i);
            rule_t *r = (rule_t *)calloc(1, sizeof(rule_t));
            if (!r) continue;

            r->id = i + 1;
            r->enabled = 1;

            cJSON *proc = cJSON_GetObjectItemCaseSensitive(item, "process");
            cJSON *ip   = cJSON_GetObjectItemCaseSensitive(item, "ip");
            cJSON *port = cJSON_GetObjectItemCaseSensitive(item, "port");
            cJSON *proto = cJSON_GetObjectItemCaseSensitive(item, "protocol");
            cJSON *action = cJSON_GetObjectItemCaseSensitive(item, "action");

            if (cJSON_IsString(proc)) strncpy(r->process, proc->valuestring, sizeof(r->process) - 1);
            else strcpy(r->process, "*");

            if (cJSON_IsString(ip)) strncpy(r->ip, ip->valuestring, sizeof(r->ip) - 1);
            else strcpy(r->ip, "*");
            r->ip_ranges = ip_ranges_compile(r->ip);

            if (cJSON_IsString(port)) strncpy(r->port, port->valuestring, sizeof(r->port) - 1);
            else strcpy(r->port, "*");

            r->protocol = cJSON_IsString(proto) ? parse_protocol(proto->valuestring) : RULE_PROTO_BOTH;
            r->action = cJSON_IsString(action) ? parse_action(action->valuestring) : RULE_ACTION_PROXY;

            r->next = NULL;
            if (!cfg->rules) { cfg->rules = r; tail = r; }
            else { tail->next = r; tail = r; }
        }
    }

    cJSON_Delete(root);

    resolve_ip(cfg->proxy.address, &cfg->proxy.ip_addr);
    resolve_ip(cfg->dns.redirect_address, &cfg->dns.redirect_ip_addr);

    return ERR_OK;
}

void config_free(app_config_t *cfg) {
    rule_t *r = cfg->rules;
    while (r) {
        rule_t *next = r->next;
        ip_ranges_free(r->ip_ranges);
        free(r);
        r = next;
    }
    cfg->rules = NULL;
}

void config_apply_cli(app_config_t *cfg, const char *proxy_str, const char *dns_str, int verbosity) {
    if (proxy_str) {
        char tmp[128];
        strncpy(tmp, proxy_str, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        char *colon = strrchr(tmp, ':');
        if (colon) {
            *colon = '\0';
            strncpy(cfg->proxy.address, tmp, sizeof(cfg->proxy.address) - 1);
            cfg->proxy.port = (uint16_t)atoi(colon + 1);
        }
        resolve_ip(cfg->proxy.address, &cfg->proxy.ip_addr);
    }

    if (dns_str) {
        cfg->dns.enabled = 1;
        char tmp[128];
        strncpy(tmp, dns_str, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        char *colon = strrchr(tmp, ':');
        if (colon) {
            *colon = '\0';
            strncpy(cfg->dns.redirect_address, tmp, sizeof(cfg->dns.redirect_address) - 1);
            cfg->dns.redirect_port = (uint16_t)atoi(colon + 1);
        }
        resolve_ip(cfg->dns.redirect_address, &cfg->dns.redirect_ip_addr);
    }

    if (verbosity >= 0) {
        if (verbosity > LOG_TRACE) verbosity = LOG_TRACE;
        cfg->log_level = verbosity;
    }
}

void config_resolve_addresses(app_config_t *cfg) {
    resolve_ip(cfg->proxy.address, &cfg->proxy.ip_addr);
    resolve_ip(cfg->dns.redirect_address, &cfg->dns.redirect_ip_addr);
}

void config_dump(const app_config_t *cfg) {
    LOG_INFO("=== WinTProxy Configuration ===");
    LOG_INFO("SOCKS5 proxy: %s:%u", cfg->proxy.address, cfg->proxy.port);
    LOG_INFO("DNS hijacking: %s", cfg->dns.enabled ? "enabled" : "disabled");
    if (cfg->dns.enabled) {
        LOG_INFO("  redirect to: %s:%u", cfg->dns.redirect_address, cfg->dns.redirect_port);
    }
    LOG_INFO("Default action: %s",
        cfg->default_action == RULE_ACTION_PROXY ? "proxy" :
        cfg->default_action == RULE_ACTION_DIRECT ? "direct" : "block");
    LOG_INFO("Bypass private IPs: %s", cfg->bypass_private_ips ? "enabled" : "disabled");

    int count = 0;
    for (rule_t *r = cfg->rules; r; r = r->next) {
        LOG_INFO("  Rule #%d: process=%s ip=%s port=%s proto=%s action=%s",
            r->id, r->process, r->ip, r->port,
            r->protocol == RULE_PROTO_TCP ? "tcp" :
            r->protocol == RULE_PROTO_UDP ? "udp" : "both",
            r->action == RULE_ACTION_PROXY ? "proxy" :
            r->action == RULE_ACTION_DIRECT ? "direct" : "block");
        count++;
    }
    LOG_INFO("Total rules: %d", count);
}
