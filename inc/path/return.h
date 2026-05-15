#ifndef WINTPROXY_PATH_RETURN_H
#define WINTPROXY_PATH_RETURN_H

#include "divert/adapter.h"
#include "flow/action.h"
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

void path_plan_return(divert_engine_t *engine, packet_ctx_t *ctx,
                      WINDIVERT_ADDRESS *addr, int is_tcp,
                      traffic_action_t *action);

#ifdef __cplusplus
}
#endif

#endif
