/*
 * Traffic action model — describes what the executor should do with a packet.
 * The ndisapi INTERMEDIATE_BUFFER carries per-packet direction and adapter handle.
 */
#ifndef WINTPROXY_FLOW_ACTION_H
#define WINTPROXY_FLOW_ACTION_H

#include <stdint.h>
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ndisapi_packet_block_s;

typedef enum {
    TRAFFIC_ACTION_PASS = 0,
    TRAFFIC_ACTION_DROP,
    TRAFFIC_ACTION_REWRITE_SEND,
    TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY,
    TRAFFIC_ACTION_FORWARD_DNS_TO_RESOLVER,
    TRAFFIC_ACTION_INJECT_DNS_RESPONSE
} traffic_action_type_t;

typedef enum {
    TRAFFIC_SEND_DEFAULT = 0,
    TRAFFIC_SEND_TO_ADAPTER,
    TRAFFIC_SEND_TO_MSTCP
} traffic_send_target_t;

typedef enum {
    TRAFFIC_PACKET_REWRITE_IP_SRC         = 1U << 0,
    TRAFFIC_PACKET_REWRITE_IP_DST         = 1U << 1,
    TRAFFIC_PACKET_REWRITE_TCP_SPORT      = 1U << 2,
    TRAFFIC_PACKET_REWRITE_TCP_DPORT      = 1U << 3,
    TRAFFIC_PACKET_REWRITE_UDP_SPORT      = 1U << 4,
    TRAFFIC_PACKET_REWRITE_UDP_DPORT      = 1U << 5,
    TRAFFIC_PACKET_REWRITE_SWAP_ETH       = 1U << 6,
    TRAFFIC_PACKET_REWRITE_CLAMP_TCP_MSS   = 1U << 7
} traffic_packet_rewrite_flag_t;

typedef struct {
    uint32_t flags;
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t tcp_sport;
    uint16_t tcp_dport;
    uint16_t udp_sport;
    uint16_t udp_dport;
    uint16_t tcp_mss;
} traffic_packet_rewrite_t;

typedef struct {
    uint16_t src_port;
    uint32_t original_dns_ip;
    uint16_t original_dns_port;
    uint32_t client_ip;
    HANDLE   adapter_handle;
} traffic_dns_forward_t;

typedef struct {
    const uint8_t *dns_payload;
    int           dns_len;
    uint16_t      dns_txid;
    uint32_t      original_dns_ip;
    uint16_t      original_dns_port;
    uint32_t      client_ip;
    uint16_t      client_port;
    HANDLE        adapter_handle;
} traffic_dns_response_t;

/*
 * Action descriptor — produced by planners, consumed by executor.
 * Deliberately exposes PINTERMEDIATE_BUFFER (ndisapi internals) to avoid
 * indirection in the hot path.  Callers treat ndis_buf and packet_ctx_t
 * as opaque handles; only the executor and packet module manipulate them.
 */
typedef struct {
    traffic_action_type_t  type;
    traffic_send_target_t  send_target;
    traffic_packet_rewrite_t rewrite;
    packet_ctx_t          *ctx;
    uint8_t               *packet;
    UINT                   packet_len;
    PINTERMEDIATE_BUFFER   ndis_buf;     /* carries direction + adapter handle */
    struct ndisapi_packet_block_s *owner_block;
    const char            *context;
    traffic_dns_forward_t  dns_forward;
    traffic_dns_response_t dns_response;
} traffic_action_t;

/* === Action constructors === */
void traffic_action_pass(traffic_action_t *action, packet_ctx_t *ctx,
                         PINTERMEDIATE_BUFFER ndis_buf, const char *context);
void traffic_action_pass_observed(traffic_action_t *action,
                                  const packet_observation_t *obs,
                                  const char *context);
void traffic_action_pass_raw(traffic_action_t *action, uint8_t *packet,
                             UINT packet_len,
                             PINTERMEDIATE_BUFFER ndis_buf,
                             const char *context);
void traffic_action_rewrite_send(traffic_action_t *action, packet_ctx_t *ctx,
                                 PINTERMEDIATE_BUFFER ndis_buf,
                                 const char *context);
void traffic_action_rewrite_send_observed(traffic_action_t *action,
                                          const packet_observation_t *obs,
                                          const char *context);
void traffic_action_drop(traffic_action_t *action, packet_ctx_t *ctx,
                         PINTERMEDIATE_BUFFER ndis_buf, const char *context);
void traffic_action_drop_observed(traffic_action_t *action,
                                  const packet_observation_t *obs,
                                  const char *context);
void traffic_action_forward_udp(traffic_action_t *action, packet_ctx_t *ctx,
                                PINTERMEDIATE_BUFFER ndis_buf,
                                const char *context);
void traffic_action_forward_udp_observed(traffic_action_t *action,
                                         const packet_observation_t *obs,
                                         const char *context);
void traffic_action_forward_dns(traffic_action_t *action, packet_ctx_t *ctx,
                                PINTERMEDIATE_BUFFER ndis_buf,
                                const traffic_dns_forward_t *forward,
                                const char *context);
void traffic_action_forward_dns_observed(traffic_action_t *action,
                                         const packet_observation_t *obs,
                                         const traffic_dns_forward_t *forward,
                                         const char *context);
void traffic_action_inject_dns_response(traffic_action_t *action,
                                        const uint8_t *dns_payload,
                                        int dns_len,
                                        uint16_t dns_txid,
                                        uint32_t original_dns_ip,
                                        uint16_t original_dns_port,
                                        uint32_t client_ip,
                                        uint16_t client_port,
                                        HANDLE adapter_handle,
                                        const char *context);
void traffic_action_set_send_target(traffic_action_t *action,
                                    traffic_send_target_t target);
void traffic_action_rewrite_ip_src(traffic_action_t *action, uint32_t ip);
void traffic_action_rewrite_ip_dst(traffic_action_t *action, uint32_t ip);
void traffic_action_rewrite_tcp_sport(traffic_action_t *action, uint16_t port);
void traffic_action_rewrite_tcp_dport(traffic_action_t *action, uint16_t port);
void traffic_action_rewrite_udp_sport(traffic_action_t *action, uint16_t port);
void traffic_action_rewrite_udp_dport(traffic_action_t *action, uint16_t port);
void traffic_action_rewrite_swap_eth(traffic_action_t *action);
void traffic_action_rewrite_clamp_tcp_mss(traffic_action_t *action, uint16_t mss);

#ifdef __cplusplus
}
#endif

#endif /* WINTPROXY_FLOW_ACTION_H */
