/*
 * Flow planner — dispatches classified packets to path/DNS planners.
 */
#include "flow/plan.h"
#include "dns/plan.h"
#include "path/bypass.h"
#include "path/classify.h"
#include "path/proxy.h"
#include "path/return.h"

void traffic_plan_packet(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                         traffic_action_t *action) {
    traffic_class_t cls = traffic_classify_packet(engine, ctx);

    switch (cls) {
    case TRAFFIC_CLASS_INBOUND:
        dns_plan_inbound_or_response(engine, ctx, 0, action);
        break;
    case TRAFFIC_CLASS_DNS_RESPONSE:
        dns_plan_inbound_or_response(engine, ctx, 1, action);
        break;
    case TRAFFIC_CLASS_TCP_DNS_RETURN:
        dns_plan_tcp_return(engine, ctx, action);
        break;
    case TRAFFIC_CLASS_TCP_RETURN:
        path_plan_return(engine, ctx, 1, action);
        break;
    case TRAFFIC_CLASS_UDP_RETURN:
        path_plan_return(engine, ctx, 0, action);
        break;
    case TRAFFIC_CLASS_SELF_PROXY:
        path_plan_bypass(engine, ctx, action, "self-proxy direct");
        break;
    case TRAFFIC_CLASS_SELF_RELAY:
        path_plan_bypass(engine, ctx, action, "self-relay direct");
        break;
    case TRAFFIC_CLASS_SELF_DNS:
        path_plan_bypass(engine, ctx, action, "self-dns direct");
        break;
    case TRAFFIC_CLASS_DNS_QUERY_UDP:
        dns_plan_udp_query(engine, ctx, action);
        break;
    case TRAFFIC_CLASS_DNS_QUERY_TCP:
        dns_plan_tcp_query(engine, ctx, action);
        break;
    case TRAFFIC_CLASS_NON_PROXYABLE:
        path_plan_bypass(engine, ctx, action, "non-proxyable direct");
        break;
    case TRAFFIC_CLASS_POLICY:
        path_plan_policy(engine, ctx, action);
        break;
    }
}
