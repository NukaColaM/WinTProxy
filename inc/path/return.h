/*
 * Return-path planner — restores original tuple for relay return traffic.
 */
#ifndef WINTPROXY_PATH_RETURN_H
#define WINTPROXY_PATH_RETURN_H

#include "ndisapi/adapter.h"
#include "flow/action.h"
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

void path_plan_return(ndisapi_engine_t *engine,
                      const packet_observation_t *obs,
                      int is_tcp, traffic_action_t *action);

#ifdef __cplusplus
}
#endif

#endif /* WINTPROXY_PATH_RETURN_H */
