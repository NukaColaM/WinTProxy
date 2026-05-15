#include "path/bypass.h"

void path_plan_bypass(divert_engine_t *engine, packet_ctx_t *ctx,
                      WINDIVERT_ADDRESS *addr, traffic_action_t *action,
                      const char *reason) {
    (void)engine;
    traffic_action_pass(action, ctx, addr, reason ? reason : "bypass");
}
