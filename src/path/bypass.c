#include "path/bypass.h"
#include "app/log.h"
#include "core/util.h"

static const char *bypass_protocol_name(const packet_ctx_t *ctx) {
    if (!ctx) return "?";
    if (ctx->tcp_hdr) return "TCP";
    if (ctx->udp_hdr) return "UDP";
    return "?";
}

void path_plan_bypass(divert_engine_t *engine, packet_ctx_t *ctx,
                      WINDIVERT_ADDRESS *addr, traffic_action_t *action,
                      const char *reason) {
    (void)engine;

    if (ctx && log_is_enabled(LOG_DEBUG)) {
        char src_str[16], dst_str[16];
        ip_to_str(ctx->src_ip, src_str, sizeof(src_str));
        ip_to_str(ctx->dst_ip, dst_str, sizeof(dst_str));
        LOG_DEBUG("DIRECT: reason=%s %s %s:%u -> %s:%u",
                  reason ? reason : "bypass",
                  bypass_protocol_name(ctx),
                  src_str, ctx->src_port,
                  dst_str, ctx->dst_port);
    }

    traffic_action_pass(action, ctx, addr, reason ? reason : "bypass");
}
