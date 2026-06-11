/*
 * Traffic action constructors.
 */
#include "flow/action.h"
#include <string.h>

static void traffic_action_init(traffic_action_t *action,
                                traffic_action_type_t type,
                                packet_ctx_t *ctx,
                                PINTERMEDIATE_BUFFER ndis_buf,
                                const char *context) {
    memset(action, 0, sizeof(*action));
    action->type    = type;
    action->send_target = TRAFFIC_SEND_DEFAULT;
    action->ctx     = ctx;
    action->packet  = ctx ? ctx->packet : NULL;
    action->packet_len = ctx ? ctx->packet_len : 0;
    action->ndis_buf = ndis_buf;
    action->context  = context;
}

void traffic_action_pass(traffic_action_t *action, packet_ctx_t *ctx,
                         PINTERMEDIATE_BUFFER ndis_buf, const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_PASS, ctx, ndis_buf, context);
}

void traffic_action_pass_observed(traffic_action_t *action,
                                  const packet_observation_t *obs,
                                  const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_PASS,
                        packet_observation_context(obs),
                        obs ? obs->ndis_buf : NULL, context);
}

void traffic_action_pass_raw(traffic_action_t *action, uint8_t *packet,
                             UINT packet_len,
                             PINTERMEDIATE_BUFFER ndis_buf,
                             const char *context) {
    memset(action, 0, sizeof(*action));
    action->type       = TRAFFIC_ACTION_PASS;
    action->send_target = TRAFFIC_SEND_DEFAULT;
    action->packet     = packet;
    action->packet_len = packet_len;
    action->ndis_buf   = ndis_buf;
    action->context    = context;
}

void traffic_action_set_send_target(traffic_action_t *action,
                                    traffic_send_target_t target) {
    if (!action) return;
    action->send_target = target;
}

void traffic_action_rewrite_ip_src(traffic_action_t *action, uint32_t ip) {
    if (!action) return;
    action->rewrite.flags |= TRAFFIC_PACKET_REWRITE_IP_SRC;
    action->rewrite.ip_src = ip;
}

void traffic_action_rewrite_ip_dst(traffic_action_t *action, uint32_t ip) {
    if (!action) return;
    action->rewrite.flags |= TRAFFIC_PACKET_REWRITE_IP_DST;
    action->rewrite.ip_dst = ip;
}

void traffic_action_rewrite_tcp_sport(traffic_action_t *action, uint16_t port) {
    if (!action) return;
    action->rewrite.flags |= TRAFFIC_PACKET_REWRITE_TCP_SPORT;
    action->rewrite.tcp_sport = port;
}

void traffic_action_rewrite_tcp_dport(traffic_action_t *action, uint16_t port) {
    if (!action) return;
    action->rewrite.flags |= TRAFFIC_PACKET_REWRITE_TCP_DPORT;
    action->rewrite.tcp_dport = port;
}

void traffic_action_rewrite_udp_sport(traffic_action_t *action, uint16_t port) {
    if (!action) return;
    action->rewrite.flags |= TRAFFIC_PACKET_REWRITE_UDP_SPORT;
    action->rewrite.udp_sport = port;
}

void traffic_action_rewrite_udp_dport(traffic_action_t *action, uint16_t port) {
    if (!action) return;
    action->rewrite.flags |= TRAFFIC_PACKET_REWRITE_UDP_DPORT;
    action->rewrite.udp_dport = port;
}

void traffic_action_rewrite_swap_eth(traffic_action_t *action) {
    if (!action) return;
    action->rewrite.flags |= TRAFFIC_PACKET_REWRITE_SWAP_ETH;
}

void traffic_action_rewrite_clamp_tcp_mss(traffic_action_t *action, uint16_t mss) {
    if (!action) return;
    action->rewrite.flags |= TRAFFIC_PACKET_REWRITE_CLAMP_TCP_MSS;
    action->rewrite.tcp_mss = mss;
}

void traffic_action_rewrite_send(traffic_action_t *action, packet_ctx_t *ctx,
                                 PINTERMEDIATE_BUFFER ndis_buf,
                                 const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_REWRITE_SEND, ctx, ndis_buf, context);
}

void traffic_action_rewrite_send_observed(traffic_action_t *action,
                                          const packet_observation_t *obs,
                                          const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_REWRITE_SEND,
                        packet_observation_context(obs),
                        obs ? obs->ndis_buf : NULL, context);
}

void traffic_action_drop(traffic_action_t *action, packet_ctx_t *ctx,
                         PINTERMEDIATE_BUFFER ndis_buf, const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_DROP, ctx, ndis_buf, context);
}

void traffic_action_drop_observed(traffic_action_t *action,
                                  const packet_observation_t *obs,
                                  const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_DROP,
                        packet_observation_context(obs),
                        obs ? obs->ndis_buf : NULL, context);
}

void traffic_action_forward_udp(traffic_action_t *action, packet_ctx_t *ctx,
                                PINTERMEDIATE_BUFFER ndis_buf,
                                const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY,
                        ctx, ndis_buf, context);
}

void traffic_action_forward_udp_observed(traffic_action_t *action,
                                         const packet_observation_t *obs,
                                         const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY,
                        packet_observation_context(obs),
                        obs ? obs->ndis_buf : NULL, context);
}

void traffic_action_forward_dns(traffic_action_t *action, packet_ctx_t *ctx,
                                PINTERMEDIATE_BUFFER ndis_buf,
                                const traffic_dns_forward_t *forward,
                                const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_FORWARD_DNS_TO_RESOLVER,
                        ctx, ndis_buf, context);
    if (forward) action->dns_forward = *forward;
}

void traffic_action_forward_dns_observed(traffic_action_t *action,
                                         const packet_observation_t *obs,
                                         const traffic_dns_forward_t *forward,
                                         const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_FORWARD_DNS_TO_RESOLVER,
                        packet_observation_context(obs),
                        obs ? obs->ndis_buf : NULL, context);
    if (forward) action->dns_forward = *forward;
}

void traffic_action_inject_dns_response(traffic_action_t *action,
                                        const uint8_t *dns_payload,
                                        int dns_len,
                                        uint16_t dns_txid,
                                        uint32_t original_dns_ip,
                                        uint16_t original_dns_port,
                                        uint32_t client_ip,
                                        uint16_t client_port,
                                        HANDLE adapter_handle,
                                        const char *context) {
    memset(action, 0, sizeof(*action));
    action->type = TRAFFIC_ACTION_INJECT_DNS_RESPONSE;
    action->context = context;
    action->dns_response.dns_payload = dns_payload;
    action->dns_response.dns_len = dns_len;
    action->dns_response.dns_txid = dns_txid;
    action->dns_response.original_dns_ip = original_dns_ip;
    action->dns_response.original_dns_port = original_dns_port;
    action->dns_response.client_ip = client_ip;
    action->dns_response.client_port = client_port;
    action->dns_response.adapter_handle = adapter_handle;
}
