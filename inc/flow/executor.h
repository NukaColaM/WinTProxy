#ifndef WINTPROXY_FLOW_EXECUTOR_H
#define WINTPROXY_FLOW_EXECUTOR_H

#include "divert/adapter.h"
#include "flow/action.h"

#ifdef __cplusplus
extern "C" {
#endif

void traffic_execute_action(divert_engine_t *engine, traffic_action_t *action);

#ifdef __cplusplus
}
#endif

#endif
