#ifndef WINTPROXY_CONFIG_H
#define WINTPROXY_CONFIG_H

#include <stdint.h>
#include <stddef.h>
#include "common.h"

#define RULE_PROCESS_TOKEN_MAX  16
#define RULE_IP_RANGE_MAX       32
#define RULE_PORT_RANGE_MAX     32

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

typedef enum {
    RULE_PROCESS_ANY = 0,
    RULE_PROCESS_EXACT,
    RULE_PROCESS_PREFIX,
    RULE_PROCESS_SUFFIX,
    RULE_PROCESS_CONTAINS
} rule_process_match_t;

typedef struct {
    rule_process_match_t type;
    char                 text[256];
    size_t               len;
} process_pattern_t;

typedef struct {
    uint32_t start;
    uint32_t end;
} ip_range_t;

typedef struct {
    uint16_t start;
    uint16_t end;
} port_range_t;

typedef struct {
    int             id;
    char            process[256];
    char            ip[256];
    char            port[128];
    rule_protocol_t protocol;
    rule_action_t   action;
    int             enabled;
    int             process_any;
    process_pattern_t process_patterns[RULE_PROCESS_TOKEN_MAX];
    size_t          process_pattern_count;
    int             ip_any;
    ip_range_t      ip_ranges[RULE_IP_RANGE_MAX];
    size_t          ip_range_count;
    int             port_any;
    port_range_t    port_ranges[RULE_PORT_RANGE_MAX];
    size_t          port_range_count;
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
    size_t         rule_count;
    rule_action_t  default_action;
    int            log_level;
    char           log_file[260];
    int            bypass_private_ips;
} app_config_t;

error_t config_load(app_config_t *cfg, const char *path);
void    config_set_defaults(app_config_t *cfg);
void    config_free(app_config_t *cfg);
error_t config_apply_cli(app_config_t *cfg, const char *proxy_str, const char *dns_str, int verbosity);
void    config_dump(const app_config_t *cfg);

#endif
