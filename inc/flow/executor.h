/*
 * Flow executor header — dispatches traffic actions using ndisapi send primitives.
 */
#ifndef WINTPROXY_FLOW_EXECUTOR_H
#define WINTPROXY_FLOW_EXECUTOR_H

#include "ndisapi/adapter.h"
#include "flow/action.h"

#ifdef __cplusplus
extern "C" {
#endif

void traffic_execute_action(ndisapi_engine_t *engine, traffic_action_t *action);

#ifdef __cplusplus
}
#endif

#endif /* WINTPROXY_FLOW_EXECUTOR_H */
