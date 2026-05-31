/*
 * DNS plan — UDP/TCP DNS intercept and redirection.
 */
#ifndef WINTPROXY_DNS_PLAN_H
#define WINTPROXY_DNS_PLAN_H

#include "ndisapi/adapter.h"
#include "flow/action.h"
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

void dns_plan_udp_query(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                        traffic_action_t *action);
void dns_plan_tcp_query(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                        traffic_action_t *action);
void dns_plan_inbound_or_response(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                                  int is_dns_response, traffic_action_t *action);
void dns_plan_tcp_return(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                         traffic_action_t *action);

#ifdef __cplusplus
}
#endif

#endif /* WINTPROXY_DNS_PLAN_H */
