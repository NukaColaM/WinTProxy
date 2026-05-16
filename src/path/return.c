#include "path/return.h"
#include "app/log.h"
#include "core/util.h"
#include <winsock2.h>

void path_plan_return(divert_engine_t *engine, packet_ctx_t *ctx,
                      WINDIVERT_ADDRESS *addr, int is_tcp,
                      traffic_action_t *action) {
    uint8_t proto_num = is_tcp ? 6 : 17;
    conntrack_entry_t entry;
    error_t err;

    if (is_tcp) {
        err = conntrack_get_full_key(engine->conntrack, LOOPBACK_ADDR, ctx->dst_port,
                                     LOOPBACK_ADDR, ctx->src_port, proto_num, &entry);
    } else {
        err = conntrack_get_full(engine->conntrack, ctx->dst_ip, ctx->dst_port, proto_num, &entry);
    }
    if (err != ERR_OK) {
        LOG_WARN("%s return: no conntrack for dst_port %u", is_tcp ? "TCP" : "UDP", ctx->dst_port);
        traffic_action_drop(action, ctx, addr, is_tcp ? "TCP return missing conntrack" : "UDP return missing conntrack");
        return;
    }

    ctx->ip_hdr->SrcAddr = entry.orig_dst_ip;
    ctx->ip_hdr->DstAddr = entry.src_ip;

    if (is_tcp) {
        ctx->tcp_hdr->SrcPort = htons(entry.orig_dst_port);
        ctx->tcp_hdr->DstPort = htons(entry.client_port);
        packet_clamp_tcp_mss(ctx, WTP_TCP_MSS_CLAMP);
        conntrack_touch_key(engine->conntrack, entry.key_src_ip, entry.src_port,
                            entry.key_dst_ip, entry.key_dst_port, proto_num);
        conntrack_touch_key(engine->conntrack, LOOPBACK_ADDR, entry.relay_src_port,
                            LOOPBACK_ADDR, engine->tcp_relay_port, proto_num);
    } else {
        ctx->udp_hdr->SrcPort = htons(entry.orig_dst_port);
        conntrack_touch(engine->conntrack, entry.key_src_ip, ctx->dst_port, proto_num);
        if (entry.src_ip != entry.key_src_ip) {
            conntrack_touch(engine->conntrack, entry.src_ip, ctx->dst_port, proto_num);
        }
    }

    addr->Outbound = 0;
    addr->Loopback = 0;
    addr->Network.IfIdx = entry.if_idx;
    addr->Network.SubIfIdx = entry.sub_if_idx;

    char orig_dst_str[16], orig_src_str[16];
    ip_to_str(entry.orig_dst_ip, orig_dst_str, sizeof(orig_dst_str));
    ip_to_str(entry.src_ip, orig_src_str, sizeof(orig_src_str));
    LOG_TRACE("%s return: rewrite 127.0.0.1:%u -> %s:%u, dst -> %s, IfIdx=%lu",
        is_tcp ? "TCP" : "UDP",
        is_tcp ? engine->tcp_relay_port : engine->udp_relay_port,
        orig_dst_str, entry.orig_dst_port, orig_src_str, (unsigned long)entry.if_idx);

    traffic_action_rewrite_send(action, ctx, addr, is_tcp ? "TCP return" : "UDP return");
}
