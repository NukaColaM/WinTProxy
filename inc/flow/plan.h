#ifndef WINTPROXY_FLOW_PLAN_H
#define WINTPROXY_FLOW_PLAN_H

#include "divert/adapter.h"
#include "flow/action.h"
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

void traffic_plan_packet(divert_engine_t *engine, packet_ctx_t *ctx,
                         WINDIVERT_ADDRESS *addr, traffic_action_t *action);

#ifdef __cplusplus
}
#endif

#endif
