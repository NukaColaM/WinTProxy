/*
 * Bypass path — passes packets through.
 *
 * For self-traffic (SELF_PROXY, SELF_RELAY, SELF_DNS) where the
 * destination is a loopback address, the packet originates from MSTCP
 * and must be delivered back to MSTCP for local loopback delivery.
 * Without this redirect, WinpkFilter tunnel mode sends the packet to
 * the physical adapter, which silently drops loopback packets.
 *
 * For NON_PROXYABLE traffic (broadcast, multicast, private IPs that
 * are not loopback), the packet should go to the physical adapter as
 * usual — these are genuine network transmissions.
 */
#include "path/bypass.h"
#include "path/classify.h"
#include "app/log.h"
#include "core/util.h"
#include "ndisapi/ndisapi.h"

void path_plan_bypass(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                      traffic_action_t *action, const char *reason) {
    (void)engine;

    if (ctx && log_is_enabled(LOG_DEBUG)) {
        char src_str[16], dst_str[16];
        ip_to_str(ctx->src_ip, src_str, sizeof(src_str));
        ip_to_str(ctx->dst_ip, dst_str, sizeof(dst_str));
        LOG_TRACE("DIRECT [%s]: reason=%s %s %s:%u -> %s:%u",
                  adapter_name_for_handle(engine, ctx->adapter_handle),
                  reason ? reason : "bypass",
                  ctx->tcp_hdr ? "TCP" : "UDP",
                  src_str, ctx->src_port,
                  dst_str, ctx->dst_port);
    }

    /*
     * Self-traffic with a loopback destination originates from MSTCP and
     * must be delivered back to MSTCP for local processing.  If we leave
     * the ON_SEND flag set, send_buf() routes the packet to the physical
     * adapter, which silently drops loopback destinations.
     *
     * Only flip the direction for packets destined to loopback addresses
     * (127.0.0.0/8).  Other self-traffic (e.g. proxy on a LAN IP) and
     * all NON_PROXYABLE traffic should keep their original direction so
     * they reach the physical adapter.
     */
    if (ctx && ctx->ndis_buf &&
        (ctx->ndis_buf->m_dwDeviceFlags & PACKET_FLAG_ON_SEND) &&
        (ctx->dst_ip & 0x0000007FU) == 0x0000007FU) {
        /* 0x7F in the low byte (little-endian network order) = 127.x.x.x */
        ctx->ndis_buf->m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    }

    traffic_action_pass(action, ctx,
                        ctx ? ctx->ndis_buf : NULL,
                        reason ? reason : "bypass");
}
