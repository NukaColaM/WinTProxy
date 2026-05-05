#ifndef WINTPROXY_CONFIG_H
#define WINTPROXY_CONFIG_H

#include <stdint.h>
#include "common.h"

typedef enum {
    RULE_ACTION_PROXY  = 0,
    RULE_ACTION_DIRECT = 1,
    RULE_ACTION_BLOCK  = 2
} rule_action_t;

typedef enum {
    RULE_PROTO_BOTH = 0,
    RULE_PROTO_TCP  = 1,
    RULE_PROTO_UDP  = 2
} rule_protocol_t;

typedef struct ip_range_s {
    uint32_t            start;
    uint32_t            end;
    struct ip_range_s  *next;
} ip_range_t;

typedef struct rule_s {
    int             id;
    char            process[256];
    char            ip[256];
    char            port[128];
    rule_protocol_t protocol;
    rule_action_t   action;
    int             enabled;
    ip_range_t     *ip_ranges;
    struct rule_s  *next;
} rule_t;

typedef struct {
    char     address[64];
    uint16_t port;
    uint32_t ip_addr;
} proxy_config_t;

typedef struct {
    int      enabled;
    char     redirect_address[64];
    uint16_t redirect_port;
    uint32_t redirect_ip_addr;
} dns_config_t;

typedef struct {
    proxy_config_t proxy;
    dns_config_t   dns;
    rule_t        *rules;
    rule_action_t  default_action;
    int            log_level;
    char           log_file[260];
    int            bypass_private_ips;
} app_config_t;

error_t config_load(app_config_t *cfg, const char *path);
void    config_set_defaults(app_config_t *cfg);
void    config_free(app_config_t *cfg);
void    config_apply_cli(app_config_t *cfg, const char *proxy_str, const char *dns_str, int verbosity);
void    config_resolve_addresses(app_config_t *cfg);
void    config_dump(const app_config_t *cfg);

#endif
