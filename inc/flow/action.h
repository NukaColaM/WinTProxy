#ifndef WINTPROXY_FLOW_ACTION_H
#define WINTPROXY_FLOW_ACTION_H

#include <stdint.h>
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TRAFFIC_ACTION_PASS = 0,
    TRAFFIC_ACTION_DROP,
    TRAFFIC_ACTION_REWRITE_SEND,
    TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY,
    TRAFFIC_ACTION_FORWARD_DNS_TO_RESOLVER
} traffic_action_type_t;

typedef struct {
    uint16_t src_port;
    uint32_t original_dns_ip;
    uint16_t original_dns_port;
    uint32_t client_ip;
    uint32_t if_idx;
    uint32_t sub_if_idx;
} traffic_dns_forward_t;

typedef struct {
    traffic_action_type_t type;
    packet_ctx_t         *ctx;
    uint8_t              *packet;
    UINT                  packet_len;
    WINDIVERT_ADDRESS    *addr;
    const char           *context;
    traffic_dns_forward_t dns_forward;
} traffic_action_t;

void traffic_action_pass(traffic_action_t *action, packet_ctx_t *ctx,
                         WINDIVERT_ADDRESS *addr, const char *context);
void traffic_action_pass_raw(traffic_action_t *action, uint8_t *packet, UINT packet_len,
                             WINDIVERT_ADDRESS *addr, const char *context);
void traffic_action_rewrite_send(traffic_action_t *action, packet_ctx_t *ctx,
                                 WINDIVERT_ADDRESS *addr, const char *context);
void traffic_action_drop(traffic_action_t *action, packet_ctx_t *ctx,
                         WINDIVERT_ADDRESS *addr, const char *context);
void traffic_action_forward_udp(traffic_action_t *action, packet_ctx_t *ctx,
                                WINDIVERT_ADDRESS *addr, const char *context);
void traffic_action_forward_dns(traffic_action_t *action, packet_ctx_t *ctx,
                                WINDIVERT_ADDRESS *addr, const traffic_dns_forward_t *forward,
                                const char *context);

#ifdef __cplusplus
}
#endif

#endif
