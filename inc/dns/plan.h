#ifndef WINTPROXY_DNS_PLAN_H
#define WINTPROXY_DNS_PLAN_H

#include "divert/adapter.h"
#include "flow/action.h"
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

void dns_plan_udp_query(divert_engine_t *engine, packet_ctx_t *ctx,
                        WINDIVERT_ADDRESS *addr, traffic_action_t *action);
void dns_plan_tcp_query(divert_engine_t *engine, packet_ctx_t *ctx,
                        WINDIVERT_ADDRESS *addr, traffic_action_t *action);
void dns_plan_udp_response_loopback(divert_engine_t *engine, packet_ctx_t *ctx,
                                    WINDIVERT_ADDRESS *addr, traffic_action_t *action);
void dns_plan_inbound_or_response(divert_engine_t *engine, packet_ctx_t *ctx,
                                  WINDIVERT_ADDRESS *addr, int is_dns_response,
                                  traffic_action_t *action);
void dns_plan_tcp_return(divert_engine_t *engine, packet_ctx_t *ctx,
                         WINDIVERT_ADDRESS *addr, traffic_action_t *action);

#ifdef __cplusplus
}
#endif

#endif
