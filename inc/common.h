#ifndef WINTPROXY_COMMON_H
#define WINTPROXY_COMMON_H

#define WINTPROXY_VERSION  "v0.2.0"

#include <stdint.h>

/* === Error codes ===
 * All functions that can fail return error_t.
 * ERR_OK = 0 so `if (func() != ERR_OK)` works naturally.
 * Pure lookup/query functions keep domain-specific return types.
 */
typedef enum {
    ERR_OK         =  0,
    ERR_GENERIC    = -1,
    ERR_NOT_FOUND  = -2,
    ERR_MEMORY     = -3,
    ERR_NETWORK    = -4,
    ERR_PARAM      = -5,
    ERR_PROTO      = -6,
    ERR_BUSY       = -7,
    ERR_PERMISSION = -8
} error_t;

/* === Packet type classification (for divert dispatcher) === */
typedef enum {
    PKT_INBOUND = 0,
    PKT_DNS_RESP_LOOPBACK,
    PKT_DNS_RESP,
    PKT_TCP_RETURN,
    PKT_UDP_RETURN,
    PKT_SELF_PROXY,
    PKT_SELF_RELAY,
    PKT_SELF_DNS,
    PKT_DNS_HIJACK,
    PKT_PROXY_REDIRECT,
    PKT_BYPASS
} pkt_type_t;

#endif
