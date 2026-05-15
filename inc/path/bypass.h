#ifndef WINTPROXY_PATH_BYPASS_H
#define WINTPROXY_PATH_BYPASS_H

#include "divert/adapter.h"
#include "flow/action.h"
#include "packet/context.h"
#include "windivert/windivert.h"

#ifdef __cplusplus
extern "C" {
#endif

void path_plan_bypass(divert_engine_t *engine, packet_ctx_t *ctx,
                      WINDIVERT_ADDRESS *addr, traffic_action_t *action,
                      const char *reason);

#ifdef __cplusplus
}
#endif

#endif
