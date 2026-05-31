/*
 * Flow planner — orchestrates classification and action planning.
 */
#ifndef WINTPROXY_FLOW_PLAN_H
#define WINTPROXY_FLOW_PLAN_H

#include "ndisapi/adapter.h"
#include "flow/action.h"
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ndis_buf carries per-packet direction and adapter info.
 */
void traffic_plan_packet(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                         traffic_action_t *action);

#ifdef __cplusplus
}
#endif

#endif /* WINTPROXY_FLOW_PLAN_H */
