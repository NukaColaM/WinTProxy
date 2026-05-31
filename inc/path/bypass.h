/*
 * Bypass / non-proxyable path planner.
 */
#ifndef WINTPROXY_PATH_BYPASS_H
#define WINTPROXY_PATH_BYPASS_H

#include "ndisapi/adapter.h"
#include "flow/action.h"
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

void path_plan_bypass(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                      traffic_action_t *action, const char *reason);

#ifdef __cplusplus
}
#endif

#endif /* WINTPROXY_PATH_BYPASS_H */
