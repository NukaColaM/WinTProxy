/*
 * Return-path planner — restores original tuple and delivers to MSTCP.
 *
 * Relay response traffic (ON_SEND from relay socket, src_port == relay_port)
 * is caught by the classifier.  The conntrack entry B keyed by actual IPs
 * (not LOOPBACK_ADDR) is looked up and the original client↔server tuple is
 * restored.  The packet is then sent to MSTCP so the client receives it as
 * if from the original server.
 */
#include "path/return.h"
#include "app/log.h"
#include "core/util.h"
#include <winsock2.h>

void path_plan_return(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                      int is_tcp, traffic_action_t *action) {
    conntrack_entry_t entry;
    error_t err;

    /*
     * Lookup entry B.
     *
     * For TCP, the relay's response packet has:
     *   src = client_ip:relay_port  (relay bound to INADDR_ANY)
     *   dst = server_ip:relay_src_port
     * Entry B key: (server_ip, relay_src_port, client_ip, relay_port, TCP)
     * So we look up (ctx->dst_ip, ctx->dst_port, ctx->src_ip, ctx->src_port).
     */
    if (is_tcp) {
        err = conntrack_get_tcp_proxy_return(engine->conntrack,
                                             ctx->dst_ip, ctx->dst_port,
                                             ctx->src_ip, ctx->src_port,
                                             &entry);
    } else {
        err = conntrack_get_udp_proxy_return(engine->conntrack,
                                             ctx->dst_ip, ctx->dst_port,
                                             &entry);
    }
    if (err != ERR_OK) {
        LOG_WARN("%s return: no conntrack for dst %s:%u",
                 is_tcp ? "TCP" : "UDP",
                 is_tcp ? "?" : "",
                 ctx->dst_port);
        traffic_action_drop(action, ctx, ctx->ndis_buf,
                            is_tcp ? "TCP return missing conntrack"
                                   : "UDP return missing conntrack");
        return;
    }

    if (is_tcp) {
        conntrack_touch_tcp_proxy_outbound(engine->conntrack, &entry);
        conntrack_touch_tcp_proxy_return(engine->conntrack, &entry);
    } else {
        conntrack_touch_udp_proxy_outbound(engine->conntrack, &entry);
        conntrack_touch_udp_proxy_return(engine->conntrack, &entry);
    }

    {
        char orig_dst_str[16], orig_src_str[16];
        ip_to_str(entry.orig_dst_ip, orig_dst_str, sizeof(orig_dst_str));
        ip_to_str(entry.src_ip, orig_src_str, sizeof(orig_src_str));
        LOG_TRACE("%s return: rewrite %s:%u -> %s:%u",
            is_tcp ? "TCP" : "UDP",
            orig_dst_str, entry.orig_dst_port,
            orig_src_str, entry.client_port);
    }

    traffic_action_rewrite_send(action, ctx, ctx->ndis_buf,
                                is_tcp ? "TCP return" : "UDP return");
    traffic_action_rewrite_ip_src(action, entry.orig_dst_ip);
    traffic_action_rewrite_ip_dst(action, entry.src_ip);
    if (is_tcp) {
        traffic_action_rewrite_tcp_sport(action, entry.orig_dst_port);
        traffic_action_rewrite_tcp_dport(action, entry.client_port);
        traffic_action_rewrite_clamp_tcp_mss(action, WTP_TCP_MSS_CLAMP);
    } else {
        traffic_action_rewrite_udp_sport(action, entry.orig_dst_port);
    }
    traffic_action_rewrite_swap_eth(action);
    traffic_action_set_send_target(action, TRAFFIC_SEND_TO_MSTCP);
}
