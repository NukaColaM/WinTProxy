#ifndef WINTPROXY_PATH_PROXY_H
#define WINTPROXY_PATH_PROXY_H

#include "divert/adapter.h"
#include "flow/action.h"
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

void path_plan_policy(divert_engine_t *engine, packet_ctx_t *ctx,
                      WINDIVERT_ADDRESS *addr, traffic_action_t *action);

#ifdef __cplusplus
}
#endif

#endif
