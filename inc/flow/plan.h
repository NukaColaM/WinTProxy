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
 * Observations carry stable packet facts. Actions carry the mutable frame
 * handle for execution.
 */
void traffic_plan_packet(ndisapi_engine_t *engine,
                         const packet_observation_t *obs,
                         traffic_action_t *action);

#ifdef __cplusplus
}
#endif

#endif /* WINTPROXY_FLOW_PLAN_H */
