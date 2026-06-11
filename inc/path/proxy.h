/*
 * Proxy / policy path planner.
 */
#ifndef WINTPROXY_PATH_PROXY_H
#define WINTPROXY_PATH_PROXY_H

#include "ndisapi/adapter.h"
#include "flow/action.h"
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

void path_plan_policy(ndisapi_engine_t *engine,
                      const packet_observation_t *obs,
                      traffic_action_t *action);

#ifdef __cplusplus
}
#endif

#endif /* WINTPROXY_PATH_PROXY_H */
