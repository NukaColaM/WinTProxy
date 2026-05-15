#include "flow/action.h"
#include <string.h>

static void traffic_action_init(traffic_action_t *action, traffic_action_type_t type,
                                packet_ctx_t *ctx, WINDIVERT_ADDRESS *addr,
                                const char *context) {
    memset(action, 0, sizeof(*action));
    action->type = type;
    action->ctx = ctx;
    action->packet = ctx ? ctx->packet : NULL;
    action->packet_len = ctx ? ctx->packet_len : 0;
    action->addr = addr;
    action->context = context;
}

void traffic_action_pass(traffic_action_t *action, packet_ctx_t *ctx,
                         WINDIVERT_ADDRESS *addr, const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_PASS, ctx, addr, context);
}

void traffic_action_pass_raw(traffic_action_t *action, uint8_t *packet, UINT packet_len,
                             WINDIVERT_ADDRESS *addr, const char *context) {
    memset(action, 0, sizeof(*action));
    action->type = TRAFFIC_ACTION_PASS;
    action->packet = packet;
    action->packet_len = packet_len;
    action->addr = addr;
    action->context = context;
}

void traffic_action_rewrite_send(traffic_action_t *action, packet_ctx_t *ctx,
                                 WINDIVERT_ADDRESS *addr, const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_REWRITE_SEND, ctx, addr, context);
}

void traffic_action_drop(traffic_action_t *action, packet_ctx_t *ctx,
                         WINDIVERT_ADDRESS *addr, const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_DROP, ctx, addr, context);
}

void traffic_action_forward_udp(traffic_action_t *action, packet_ctx_t *ctx,
                                WINDIVERT_ADDRESS *addr, const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY, ctx, addr, context);
}

void traffic_action_forward_dns(traffic_action_t *action, packet_ctx_t *ctx,
                                WINDIVERT_ADDRESS *addr, const traffic_dns_forward_t *forward,
                                const char *context) {
    traffic_action_init(action, TRAFFIC_ACTION_FORWARD_DNS_TO_RESOLVER, ctx, addr, context);
    if (forward) action->dns_forward = *forward;
}
