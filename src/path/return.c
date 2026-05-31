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
    uint8_t proto_num = is_tcp ? WTP_IPPROTO_TCP : WTP_IPPROTO_UDP;
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
        err = conntrack_get_full_key(engine->conntrack,
                                     ctx->dst_ip, ctx->dst_port,
                                     ctx->src_ip, ctx->src_port,
                                     proto_num, &entry);
    } else {
        /* UDP: entry B key is (server_ip, client_port), matched by
         * (ctx->dst_ip, ctx->dst_port) where ctx->dst_port = client_port
         * (relay sends to server_ip:client_port, see T4). */
        err = conntrack_get_full(engine->conntrack, ctx->dst_ip,
                                 ctx->dst_port, proto_num, &entry);
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

    /* Restore original tuple */
    ctx->ip_hdr->ip_src = entry.orig_dst_ip;
    ctx->ip_hdr->ip_dst = entry.src_ip;

    if (is_tcp) {
        ctx->tcp_hdr->th_sport = htons(entry.orig_dst_port);
        ctx->tcp_hdr->th_dport = htons(entry.client_port);
        packet_clamp_tcp_mss(ctx, WTP_TCP_MSS_CLAMP);

        /* Touch both conntrack entries to keep them alive */
        conntrack_touch_key(engine->conntrack,
                            entry.key_src_ip, entry.src_port,
                            entry.key_dst_ip, entry.key_dst_port,
                            proto_num);
        conntrack_touch_key(engine->conntrack,
                            ctx->dst_ip, ctx->dst_port,
                            ctx->src_ip, ctx->src_port,
                            proto_num);
    } else {
        ctx->udp_hdr->uh_sport = htons(entry.orig_dst_port);
        conntrack_touch(engine->conntrack, entry.key_src_ip,
                        ctx->dst_port, proto_num);
        if (entry.src_ip != entry.key_src_ip) {
            conntrack_touch(engine->conntrack, entry.src_ip,
                            ctx->dst_port, proto_num);
        }
    }

    /* Swap Ethernet MACs for the response */
    swap_ether_addrs(ctx->eth_hdr);

    /* Deliver to MSTCP (revert: this was ON_SEND, now send up the stack) */
    ctx->ndis_buf->m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;

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
}
