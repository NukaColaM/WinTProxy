#include "config.h"
#include "log.h"
#include "util.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "cJSON/cJSON.h"

#define CONFIG_FILE_MAX_BYTES (1024L * 1024L)

void config_set_defaults(app_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    safe_str_copy(cfg->proxy.address, sizeof(cfg->proxy.address), "127.0.0.1");
    cfg->proxy.port = 7890;
    cfg->proxy.ip_addr = LOOPBACK_ADDR;
    cfg->dns.enabled = 0;
    safe_str_copy(cfg->dns.redirect_address, sizeof(cfg->dns.redirect_address), "127.0.0.1");
    cfg->dns.redirect_port = 1053;
    cfg->dns.redirect_ip_addr = LOOPBACK_ADDR;
    cfg->rules = NULL;
    cfg->rule_count = 0;
    cfg->default_action = RULE_ACTION_PROXY;
    cfg->log_level = LOG_INFO;
    cfg->bypass_private_ips = 0;
}

void config_free(app_config_t *cfg) {
    free(cfg->rules);
    cfg->rules = NULL;
    cfg->rule_count = 0;
}

static char *trim(char *s) {
    char *end;
    while (*s && isspace((unsigned char)*s)) s++;
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)*(end - 1))) {
        end--;
        *end = '\0';
    }
    return s;
}

static int parse_u32_text(const char *s, unsigned long min_value, unsigned long max_value,
                          unsigned long *out) {
    char *end = NULL;
    unsigned long value;

    if (!s || !*s) return 0;
    errno = 0;
    value = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return 0;
    if (value < min_value || value > max_value) return 0;

    *out = value;
    return 1;
}

static int parse_port_text(const char *s, int allow_zero, uint16_t *out) {
    unsigned long value;
    if (!parse_u32_text(s, allow_zero ? 0UL : 1UL, 65535UL, &value)) return 0;
    *out = (uint16_t)value;
    return 1;
}

static int parse_json_port(cJSON *item, const char *name, uint16_t *out) {
    double value;

    if (!item) return 1;
    if (!cJSON_IsNumber(item)) {
        LOG_ERROR("Invalid config: %s must be a number", name);
        return 0;
    }

    value = item->valuedouble;
    if (value < 1.0 || value > 65535.0 || value != (double)item->valueint) {
        LOG_ERROR("Invalid config: %s must be an integer in range 1..65535", name);
        return 0;
    }

    *out = (uint16_t)item->valueint;
    return 1;
}

static int parse_action(const char *s, rule_action_t *out) {
    if (!s) return 0;
    if (_stricmp(s, "proxy") == 0)  { *out = RULE_ACTION_PROXY;  return 1; }
    if (_stricmp(s, "direct") == 0) { *out = RULE_ACTION_DIRECT; return 1; }
    if (_stricmp(s, "block") == 0)  { *out = RULE_ACTION_BLOCK;  return 1; }
    return 0;
}

static int parse_protocol(const char *s, rule_protocol_t *out) {
    if (!s) return 0;
    if (_stricmp(s, "both") == 0) { *out = RULE_PROTO_BOTH; return 1; }
    if (_stricmp(s, "tcp") == 0)  { *out = RULE_PROTO_TCP;  return 1; }
    if (_stricmp(s, "udp") == 0)  { *out = RULE_PROTO_UDP;  return 1; }
    return 0;
}

static int parse_log_level(const char *s, int *out) {
    if (!s) return 0;
    if (_stricmp(s, "error") == 0) { *out = LOG_ERROR; return 1; }
    if (_stricmp(s, "warn") == 0)  { *out = LOG_WARN;  return 1; }
    if (_stricmp(s, "info") == 0)  { *out = LOG_INFO;  return 1; }
    if (_stricmp(s, "debug") == 0) { *out = LOG_DEBUG; return 1; }
    if (_stricmp(s, "trace") == 0) { *out = LOG_TRACE; return 1; }
    if (_stricmp(s, "packet") == 0) { *out = LOG_PACKET; return 1; }
    return 0;
}

static int parse_ipv4_net(const char *s, uint32_t *out_net) {
    struct in_addr in;
    if (!s || inet_pton(AF_INET, s, &in) != 1) return 0;
    *out_net = in.s_addr;
    return 1;
}

static int resolve_ip_required(const char *name, const char *addr_str, uint32_t *out_ip) {
    if (!parse_ipv4_net(addr_str, out_ip)) {
        LOG_ERROR("Invalid config: %s must be an IPv4 address: %s", name, addr_str ? addr_str : "(null)");
        return 0;
    }
    return 1;
}

static int ip_range_cmp(const void *a, const void *b) {
    const ip_range_t *ra = (const ip_range_t *)a;
    const ip_range_t *rb = (const ip_range_t *)b;
    if (ra->start < rb->start) return -1;
    if (ra->start > rb->start) return 1;
    if (ra->end < rb->end) return -1;
    if (ra->end > rb->end) return 1;
    return 0;
}

static int port_range_cmp(const void *a, const void *b) {
    const port_range_t *ra = (const port_range_t *)a;
    const port_range_t *rb = (const port_range_t *)b;
    if (ra->start < rb->start) return -1;
    if (ra->start > rb->start) return 1;
    if (ra->end < rb->end) return -1;
    if (ra->end > rb->end) return 1;
    return 0;
}

static void merge_ip_ranges(rule_t *r) {
    size_t out = 0;
    if (r->ip_range_count <= 1) return;
    qsort(r->ip_ranges, r->ip_range_count, sizeof(r->ip_ranges[0]), ip_range_cmp);

    for (size_t i = 0; i < r->ip_range_count; i++) {
        ip_range_t cur = r->ip_ranges[i];
        if (out > 0 && cur.start <= r->ip_ranges[out - 1].end + 1U) {
            if (cur.end > r->ip_ranges[out - 1].end) r->ip_ranges[out - 1].end = cur.end;
        } else {
            r->ip_ranges[out++] = cur;
        }
    }
    r->ip_range_count = out;
}

static void merge_port_ranges(rule_t *r) {
    size_t out = 0;
    if (r->port_range_count <= 1) return;
    qsort(r->port_ranges, r->port_range_count, sizeof(r->port_ranges[0]), port_range_cmp);

    for (size_t i = 0; i < r->port_range_count; i++) {
        port_range_t cur = r->port_ranges[i];
        if (out > 0 && (unsigned int)cur.start <= (unsigned int)r->port_ranges[out - 1].end + 1U) {
            if (cur.end > r->port_ranges[out - 1].end) r->port_ranges[out - 1].end = cur.end;
        } else {
            r->port_ranges[out++] = cur;
        }
    }
    r->port_range_count = out;
}

static int append_ip_range(rule_t *r, uint32_t start, uint32_t end) {
    if (start > end || r->ip_range_count >= RULE_IP_RANGE_MAX) return 0;
    r->ip_ranges[r->ip_range_count].start = start;
    r->ip_ranges[r->ip_range_count].end = end;
    r->ip_range_count++;
    return 1;
}

static int append_port_range(rule_t *r, uint16_t start, uint16_t end) {
    if (start > end || r->port_range_count >= RULE_PORT_RANGE_MAX) return 0;
    r->port_ranges[r->port_range_count].start = start;
    r->port_ranges[r->port_range_count].end = end;
    r->port_range_count++;
    return 1;
}

static int parse_wildcard_ipv4(const char *token, uint32_t *start, uint32_t *end) {
    char copy[64];
    char *ctx = NULL;
    char *part;
    uint32_t start_host = 0;
    uint32_t end_host = 0;

    if (!safe_str_copy(copy, sizeof(copy), token)) return 0;

    part = strtok_s(copy, ".", &ctx);
    for (int i = 0; i < 4; i++) {
        unsigned long octet;
        uint32_t lo;
        uint32_t hi;

        if (!part) return 0;
        part = trim(part);
        if (strcmp(part, "*") == 0) {
            lo = 0;
            hi = 255;
        } else {
            if (!parse_u32_text(part, 0, 255, &octet)) return 0;
            lo = (uint32_t)octet;
            hi = (uint32_t)octet;
        }

        start_host = (start_host << 8) | lo;
        end_host = (end_host << 8) | hi;
        part = strtok_s(NULL, ".", &ctx);
    }

    if (part) return 0;
    *start = start_host;
    *end = end_host;
    return 1;
}

static int compile_ip_ranges(rule_t *r) {
    char pat_copy[256];
    char *ctx = NULL;
    char *token;

    r->ip_any = 0;
    r->ip_range_count = 0;
    if (strcmp(r->ip, "*") == 0) {
        r->ip_any = 1;
        return 1;
    }
    if (!safe_str_copy(pat_copy, sizeof(pat_copy), r->ip)) {
        LOG_ERROR("Invalid config: IP pattern is too long");
        return 0;
    }

    token = strtok_s(pat_copy, ";,", &ctx);
    while (token) {
        uint32_t start = 0;
        uint32_t end = 0;
        char *dash;
        char *slash;

        token = trim(token);
        if (!*token) goto fail;

        dash = strchr(token, '-');
        slash = strchr(token, '/');

        if (dash) {
            uint32_t start_net;
            uint32_t end_net;

            if (slash) goto fail;
            *dash = '\0';
            if (!parse_ipv4_net(trim(token), &start_net) ||
                !parse_ipv4_net(trim(dash + 1), &end_net)) {
                goto fail;
            }
            start = ipv4_net_to_host(start_net);
            end = ipv4_net_to_host(end_net);
        } else if (slash) {
            uint32_t net_addr;
            uint32_t net_host;
            uint32_t mask;
            unsigned long prefix;

            *slash = '\0';
            if (!parse_ipv4_net(trim(token), &net_addr) ||
                !parse_u32_text(trim(slash + 1), 0, 32, &prefix)) {
                goto fail;
            }

            mask = (prefix == 0) ? 0U : (0xFFFFFFFFU << (32U - (uint32_t)prefix));
            net_host = ipv4_net_to_host(net_addr);
            start = net_host & mask;
            end = start | ~mask;
        } else if (strchr(token, '*')) {
            if (!parse_wildcard_ipv4(token, &start, &end)) goto fail;
        } else {
            uint32_t exact_net;
            if (!parse_ipv4_net(token, &exact_net)) goto fail;
            start = end = ipv4_net_to_host(exact_net);
        }

        if (!append_ip_range(r, start, end)) {
            LOG_ERROR("Invalid config: too many IP ranges or invalid range: %s", r->ip);
            return 0;
        }

        token = strtok_s(NULL, ";,", &ctx);
    }

    if (r->ip_range_count == 0) goto fail;
    merge_ip_ranges(r);
    return 1;

fail:
    LOG_ERROR("Invalid config: IP pattern is malformed: %s", r->ip);
    return 0;
}

static int compile_port_ranges(rule_t *r) {
    char copy[128];
    char *ctx = NULL;
    char *token;

    r->port_any = 0;
    r->port_range_count = 0;
    if (strcmp(r->port, "*") == 0) {
        r->port_any = 1;
        return 1;
    }
    if (!safe_str_copy(copy, sizeof(copy), r->port)) {
        LOG_ERROR("Invalid config: port pattern is too long");
        return 0;
    }

    token = strtok_s(copy, ",;", &ctx);
    while (token) {
        char *dash;
        uint16_t lo;
        uint16_t hi;

        token = trim(token);
        if (!*token) {
            LOG_ERROR("Invalid config: empty port token in pattern: %s", r->port);
            return 0;
        }

        dash = strchr(token, '-');
        if (dash) {
            *dash = '\0';
            if (!parse_port_text(trim(token), 0, &lo) ||
                !parse_port_text(trim(dash + 1), 0, &hi) ||
                lo > hi) {
                LOG_ERROR("Invalid config: malformed port range: %s", r->port);
                return 0;
            }
        } else if (parse_port_text(token, 0, &lo)) {
            hi = lo;
        } else {
            LOG_ERROR("Invalid config: malformed port token: %s", r->port);
            return 0;
        }

        if (!append_port_range(r, lo, hi)) {
            LOG_ERROR("Invalid config: too many port ranges: %s", r->port);
            return 0;
        }

        token = strtok_s(NULL, ",;", &ctx);
    }

    if (r->port_range_count == 0) return 0;
    merge_port_ranges(r);
    return 1;
}

static int append_process_pattern(rule_t *r, rule_process_match_t type, const char *text) {
    process_pattern_t *p;
    if (r->process_pattern_count >= RULE_PROCESS_TOKEN_MAX) return 0;
    p = &r->process_patterns[r->process_pattern_count++];
    memset(p, 0, sizeof(*p));
    p->type = type;
    if (!safe_str_copy(p->text, sizeof(p->text), text)) return 0;
    _strlwr(p->text);
    p->len = strlen(p->text);
    return p->len > 0 || type == RULE_PROCESS_ANY;
}

static int compile_process_patterns(rule_t *r) {
    char copy[256];
    char *ctx = NULL;
    char *token;

    r->process_any = 0;
    r->process_pattern_count = 0;
    if (strcmp(r->process, "*") == 0 || _stricmp(r->process, "any") == 0) {
        r->process_any = 1;
        return 1;
    }

    if (!safe_str_copy(copy, sizeof(copy), r->process)) {
        LOG_ERROR("Invalid config: process pattern is too long");
        return 0;
    }

    token = strtok_s(copy, ",;", &ctx);
    while (token) {
        rule_process_match_t type = RULE_PROCESS_EXACT;
        size_t len;

        token = trim(token);
        len = strlen(token);
        if (len == 0) {
            token = strtok_s(NULL, ",;", &ctx);
            continue;
        }

        if (strcmp(token, "*") == 0 || _stricmp(token, "any") == 0) {
            r->process_any = 1;
            return 1;
        }

        if (token[0] == '*' && token[len - 1] == '*' && len > 2) {
            token[len - 1] = '\0';
            token++;
            type = RULE_PROCESS_CONTAINS;
        } else if (token[0] == '*' && len > 1) {
            token++;
            type = RULE_PROCESS_SUFFIX;
        } else if (token[len - 1] == '*' && len > 1) {
            token[len - 1] = '\0';
            type = RULE_PROCESS_PREFIX;
        }

        if (!append_process_pattern(r, type, token)) {
            LOG_ERROR("Invalid config: too many process patterns or token too long: %s", r->process);
            return 0;
        }

        token = strtok_s(NULL, ",;", &ctx);
    }

    if (r->process_pattern_count == 0) {
        LOG_ERROR("Invalid config: process pattern is empty: %s", r->process);
        return 0;
    }

    return 1;
}

static int parse_endpoint(const char *text, char *addr_out, size_t addr_out_len,
                          uint16_t *port_out, uint32_t *ip_out) {
    char tmp[128];
    char *colon;
    uint16_t port;

    if (!safe_str_copy(tmp, sizeof(tmp), text)) {
        LOG_ERROR("Invalid endpoint: value is too long");
        return 0;
    }

    colon = strrchr(tmp, ':');
    if (!colon || colon == tmp || colon[1] == '\0') {
        LOG_ERROR("Invalid endpoint, expected addr:port: %s", text);
        return 0;
    }

    *colon = '\0';
    if (!parse_port_text(colon + 1, 0, &port)) {
        LOG_ERROR("Invalid endpoint port: %s", text);
        return 0;
    }
    if (!resolve_ip_required("endpoint address", tmp, ip_out)) {
        return 0;
    }
    if (!safe_str_copy(addr_out, addr_out_len, tmp)) {
        LOG_ERROR("Invalid endpoint address is too long: %s", tmp);
        return 0;
    }

    *port_out = port;
    return 1;
}

static int parse_proxy_object(app_config_t *cfg, cJSON *proxy) {
    cJSON *addr;
    cJSON *port;

    if (!proxy) return 1;
    if (!cJSON_IsObject(proxy)) {
        LOG_ERROR("Invalid config: proxy must be an object");
        return 0;
    }

    addr = cJSON_GetObjectItemCaseSensitive(proxy, "address");
    port = cJSON_GetObjectItemCaseSensitive(proxy, "port");

    if (addr) {
        if (!cJSON_IsString(addr) ||
            !safe_str_copy(cfg->proxy.address, sizeof(cfg->proxy.address), addr->valuestring)) {
            LOG_ERROR("Invalid config: proxy.address must be a short IPv4 string");
            return 0;
        }
    }
    return parse_json_port(port, "proxy.port", &cfg->proxy.port);
}

static int parse_dns_object(app_config_t *cfg, cJSON *dns) {
    cJSON *enabled;
    cJSON *addr;
    cJSON *port;

    if (!dns) return 1;
    if (!cJSON_IsObject(dns)) {
        LOG_ERROR("Invalid config: dns must be an object");
        return 0;
    }

    enabled = cJSON_GetObjectItemCaseSensitive(dns, "enabled");
    addr = cJSON_GetObjectItemCaseSensitive(dns, "redirect_address");
    port = cJSON_GetObjectItemCaseSensitive(dns, "redirect_port");

    if (enabled) {
        if (!cJSON_IsBool(enabled)) {
            LOG_ERROR("Invalid config: dns.enabled must be boolean");
            return 0;
        }
        cfg->dns.enabled = cJSON_IsTrue(enabled);
    }
    if (addr) {
        if (!cJSON_IsString(addr) ||
            !safe_str_copy(cfg->dns.redirect_address, sizeof(cfg->dns.redirect_address), addr->valuestring)) {
            LOG_ERROR("Invalid config: dns.redirect_address must be a short IPv4 string");
            return 0;
        }
    }
    return parse_json_port(port, "dns.redirect_port", &cfg->dns.redirect_port);
}

static int parse_rule_object(rule_t *r, cJSON *item, int id) {
    cJSON *proc = cJSON_GetObjectItemCaseSensitive(item, "process");
    cJSON *ip = cJSON_GetObjectItemCaseSensitive(item, "ip");
    cJSON *port = cJSON_GetObjectItemCaseSensitive(item, "port");
    cJSON *proto = cJSON_GetObjectItemCaseSensitive(item, "protocol");
    cJSON *action = cJSON_GetObjectItemCaseSensitive(item, "action");
    cJSON *enabled = cJSON_GetObjectItemCaseSensitive(item, "enabled");

    memset(r, 0, sizeof(*r));
    r->id = id;
    r->enabled = 1;
    safe_str_copy(r->process, sizeof(r->process), "*");
    safe_str_copy(r->ip, sizeof(r->ip), "*");
    safe_str_copy(r->port, sizeof(r->port), "*");
    r->protocol = RULE_PROTO_BOTH;
    r->action = RULE_ACTION_PROXY;

    if (enabled) {
        if (!cJSON_IsBool(enabled)) {
            LOG_ERROR("Invalid config: rules[%d].enabled must be boolean", id - 1);
            return 0;
        }
        r->enabled = cJSON_IsTrue(enabled);
    }
    if (proc) {
        if (!cJSON_IsString(proc) ||
            !safe_str_copy(r->process, sizeof(r->process), proc->valuestring)) {
            LOG_ERROR("Invalid config: rules[%d].process must be a short string", id - 1);
            return 0;
        }
    }
    if (ip) {
        if (!cJSON_IsString(ip) ||
            !safe_str_copy(r->ip, sizeof(r->ip), ip->valuestring)) {
            LOG_ERROR("Invalid config: rules[%d].ip must be a short string", id - 1);
            return 0;
        }
    }
    if (port) {
        if (!cJSON_IsString(port) ||
            !safe_str_copy(r->port, sizeof(r->port), port->valuestring)) {
            LOG_ERROR("Invalid config: rules[%d].port must be a short string", id - 1);
            return 0;
        }
    }
    if (proto) {
        if (!cJSON_IsString(proto) || !parse_protocol(proto->valuestring, &r->protocol)) {
            LOG_ERROR("Invalid config: rules[%d].protocol must be tcp, udp, or both", id - 1);
            return 0;
        }
    }
    if (action) {
        if (!cJSON_IsString(action) || !parse_action(action->valuestring, &r->action)) {
            LOG_ERROR("Invalid config: rules[%d].action must be proxy, direct, or block", id - 1);
            return 0;
        }
    }

    return compile_process_patterns(r) && compile_ip_ranges(r) && compile_port_ranges(r);
}

static int parse_rules_array(app_config_t *cfg, cJSON *rules) {
    int count;
    rule_t *compiled;

    cfg->rules = NULL;
    cfg->rule_count = 0;
    if (!rules) return 1;
    if (!cJSON_IsArray(rules)) {
        LOG_ERROR("Invalid config: rules must be an array");
        return 0;
    }

    count = cJSON_GetArraySize(rules);
    if (count <= 0) return 1;

    compiled = (rule_t *)calloc((size_t)count, sizeof(*compiled));
    if (!compiled) return 0;

    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(rules, i);
        if (!cJSON_IsObject(item)) {
            LOG_ERROR("Invalid config: rules[%d] must be an object", i);
            free(compiled);
            return 0;
        }

        if (!parse_rule_object(&compiled[i], item, i + 1)) {
            free(compiled);
            return 0;
        }
    }

    cfg->rules = compiled;
    cfg->rule_count = (size_t)count;
    return 1;
}

error_t config_load(app_config_t *cfg, const char *path) {
    FILE *f = NULL;
    char *buf = NULL;
    long len;
    size_t got;
    cJSON *root = NULL;
    app_config_t next;
    error_t result = ERR_GENERIC;

    config_set_defaults(&next);

    f = fopen(path, "rb");
    if (!f) {
        LOG_ERROR("Cannot open config file: %s", path);
        goto done;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        LOG_ERROR("Cannot determine config file size: %s", path);
        goto done;
    }
    if (len > CONFIG_FILE_MAX_BYTES) {
        LOG_ERROR("Config file is too large: %s (%ld bytes, max %ld)", path, len, CONFIG_FILE_MAX_BYTES);
        result = ERR_PARAM;
        goto done;
    }

    buf = (char *)malloc((size_t)len + 1U);
    if (!buf) {
        result = ERR_MEMORY;
        goto done;
    }

    got = fread(buf, 1, (size_t)len, f);
    if (got != (size_t)len || ferror(f)) {
        LOG_ERROR("Cannot read complete config file: %s", path);
        goto done;
    }
    buf[len] = '\0';

    root = cJSON_Parse(buf);
    if (!root) {
        LOG_ERROR("Failed to parse config JSON: %s", cJSON_GetErrorPtr());
        goto done;
    }
    if (!cJSON_IsObject(root)) {
        LOG_ERROR("Invalid config: root must be an object");
        goto done;
    }

    if (!parse_proxy_object(&next, cJSON_GetObjectItemCaseSensitive(root, "proxy")) ||
        !parse_dns_object(&next, cJSON_GetObjectItemCaseSensitive(root, "dns"))) {
        goto done;
    }

    {
        cJSON *def_action = cJSON_GetObjectItemCaseSensitive(root, "default_action");
        if (def_action) {
            if (!cJSON_IsString(def_action) || !parse_action(def_action->valuestring, &next.default_action)) {
                LOG_ERROR("Invalid config: default_action must be proxy, direct, or block");
                goto done;
            }
        }
    }

    {
        cJSON *log_lvl = cJSON_GetObjectItemCaseSensitive(root, "log_level");
        if (log_lvl) {
            if (!cJSON_IsString(log_lvl) || !parse_log_level(log_lvl->valuestring, &next.log_level)) {
                LOG_ERROR("Invalid config: log_level must be error, warn, info, debug, trace, or packet");
                goto done;
            }
        }
    }

    {
        cJSON *log_file = cJSON_GetObjectItemCaseSensitive(root, "log_file");
        if (log_file) {
            if (!cJSON_IsString(log_file) ||
                !safe_str_copy(next.log_file, sizeof(next.log_file), log_file->valuestring)) {
                LOG_ERROR("Invalid config: log_file must be a short string");
                goto done;
            }
        }
    }

    {
        cJSON *bypass_priv = cJSON_GetObjectItemCaseSensitive(root, "bypass_private_ips");
        if (bypass_priv) {
            if (!cJSON_IsBool(bypass_priv)) {
                LOG_ERROR("Invalid config: bypass_private_ips must be boolean");
                goto done;
            }
            next.bypass_private_ips = cJSON_IsTrue(bypass_priv);
        }
    }

    if (!parse_rules_array(&next, cJSON_GetObjectItemCaseSensitive(root, "rules"))) {
        goto done;
    }

    if (!resolve_ip_required("proxy.address", next.proxy.address, &next.proxy.ip_addr) ||
        !resolve_ip_required("dns.redirect_address", next.dns.redirect_address, &next.dns.redirect_ip_addr)) {
        goto done;
    }

    config_free(cfg);
    *cfg = next;
    memset(&next, 0, sizeof(next));
    result = ERR_OK;

done:
    if (f) fclose(f);
    if (root) cJSON_Delete(root);
    free(buf);
    config_free(&next);
    return result;
}

error_t config_apply_cli(app_config_t *cfg, const char *proxy_str, const char *dns_str, int verbosity) {
    if (proxy_str) {
        char address[sizeof(cfg->proxy.address)];
        uint16_t port;
        uint32_t ip;

        if (!parse_endpoint(proxy_str, address, sizeof(address), &port, &ip)) {
            return ERR_PARAM;
        }
        safe_str_copy(cfg->proxy.address, sizeof(cfg->proxy.address), address);
        cfg->proxy.port = port;
        cfg->proxy.ip_addr = ip;
    }

    if (dns_str) {
        char address[sizeof(cfg->dns.redirect_address)];
        uint16_t port;
        uint32_t ip;

        if (!parse_endpoint(dns_str, address, sizeof(address), &port, &ip)) {
            return ERR_PARAM;
        }
        cfg->dns.enabled = 1;
        safe_str_copy(cfg->dns.redirect_address, sizeof(cfg->dns.redirect_address), address);
        cfg->dns.redirect_port = port;
        cfg->dns.redirect_ip_addr = ip;
    }

    if (verbosity >= 0) {
        if (verbosity > LOG_PACKET) verbosity = LOG_PACKET;
        cfg->log_level = verbosity;
    }

    return ERR_OK;
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

    for (size_t i = 0; i < cfg->rule_count; i++) {
        const rule_t *r = &cfg->rules[i];
        LOG_INFO("  Rule #%d: process=%s ip=%s port=%s proto=%s action=%s%s",
            r->id, r->process, r->ip, r->port,
            r->protocol == RULE_PROTO_TCP ? "tcp" :
            r->protocol == RULE_PROTO_UDP ? "udp" : "both",
            r->action == RULE_ACTION_PROXY ? "proxy" :
            r->action == RULE_ACTION_DIRECT ? "direct" : "block",
            r->enabled ? "" : " disabled");
    }
    LOG_INFO("Total rules: %u", (unsigned int)cfg->rule_count);
}
