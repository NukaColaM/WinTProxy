#include "dns/plan.h"
#include "divert/io.h"
#include "app/log.h"
#include "core/util.h"
#include <winsock2.h>

void dns_plan_udp_response_loopback(divert_engine_t *engine, packet_ctx_t *ctx,
                                    WINDIVERT_ADDRESS *addr, traffic_action_t *action) {
    uint32_t orig_dns_ip, cli_ip;
    uint16_t orig_dns_port;
    uint32_t orig_if_idx, orig_sub_if_idx;
    uint16_t dns_txid;

    if (!packet_dns_txid(ctx, &dns_txid)) {
        LOG_PACKET("DNS response (loopback): malformed payload, passing through");
        traffic_action_pass(action, ctx, addr, "DNS response loopback malformed");
        return;
    }

    if (dns_hijack_rewrite_response(engine->dns_hijack, &orig_dns_ip, &orig_dns_port,
                                     ctx->dst_port, dns_txid,
                                     &cli_ip, &orig_if_idx, &orig_sub_if_idx)) {
        char orig_str[16], cli_str[16], src_str[16];
        ip_to_str(orig_dns_ip, orig_str, sizeof(orig_str));
        ip_to_str(cli_ip, cli_str, sizeof(cli_str));
        ip_to_str(ctx->src_ip, src_str, sizeof(src_str));
        LOG_PACKET("DNS response (loopback): src %s:%u -> %s:%u, dst -> %s, IfIdx=%lu",
            src_str, ctx->src_port, orig_str, orig_dns_port, cli_str, (unsigned long)orig_if_idx);
        ctx->ip_hdr->SrcAddr = orig_dns_ip;
        ctx->udp_hdr->SrcPort = htons(orig_dns_port);
        ctx->ip_hdr->DstAddr = cli_ip;
        addr->Outbound = 0;
        addr->Loopback = 0;
        addr->Network.IfIdx = orig_if_idx;
        addr->Network.SubIfIdx = orig_sub_if_idx;
        traffic_action_rewrite_send(action, ctx, addr, "DNS response loopback");
        return;
    }

    traffic_action_pass(action, ctx, addr, "DNS response loopback");
}

void dns_plan_inbound_or_response(divert_engine_t *engine, packet_ctx_t *ctx,
                                  WINDIVERT_ADDRESS *addr, int is_dns_response,
                                  traffic_action_t *action) {
    if (is_dns_response) {
        uint32_t orig_dns_ip;
        uint16_t orig_dns_port;
        uint16_t dns_txid;
        if (packet_dns_txid(ctx, &dns_txid) &&
            dns_hijack_rewrite_response(engine->dns_hijack, &orig_dns_ip, &orig_dns_port,
                                         ctx->dst_port, dns_txid, NULL, NULL, NULL)) {
            ctx->ip_hdr->SrcAddr = orig_dns_ip;
            ctx->udp_hdr->SrcPort = htons(orig_dns_port);
            traffic_action_rewrite_send(action, ctx, addr, "inbound DNS response");
            return;
        }
    }
    traffic_action_pass(action, ctx, addr, "inbound");
}

void dns_plan_tcp_return(divert_engine_t *engine, packet_ctx_t *ctx,
                         WINDIVERT_ADDRESS *addr, traffic_action_t *action) {
    conntrack_entry_t entry;

    if (conntrack_get_full_key(engine->conntrack, ctx->dst_ip, ctx->dst_port,
                               ctx->src_ip, ctx->src_port, 6, &entry) != ERR_OK) {
        LOG_PACKET("TCP DNS return: no conntrack for dst_port %u", ctx->dst_port);
        traffic_action_drop(action, ctx, addr, "TCP DNS return missing conntrack");
        return;
    }

    ctx->ip_hdr->SrcAddr = entry.orig_dst_ip;
    ctx->ip_hdr->DstAddr = entry.src_ip;
    ctx->tcp_hdr->SrcPort = htons(entry.orig_dst_port);
    ctx->tcp_hdr->DstPort = htons(entry.client_port);

    if (engine->dns_hijack->redirect_ip == LOOPBACK_ADDR) {
        divert_set_loopback_route(engine, addr);
    } else {
        addr->Outbound = 0;
        addr->Loopback = 0;
        addr->Network.IfIdx = entry.if_idx;
        addr->Network.SubIfIdx = entry.sub_if_idx;
    }

    traffic_action_rewrite_send(action, ctx, addr, "TCP DNS return");
}

void dns_plan_udp_query(divert_engine_t *engine, packet_ctx_t *ctx,
                        WINDIVERT_ADDRESS *addr, traffic_action_t *action) {
    const uint8_t *dns_data = NULL;
    UINT dns_data_len = 0;
    uint16_t dns_txid = 0;

    packet_payload(ctx, &dns_data, &dns_data_len);
    if (!dns_data || dns_data_len < 2 || !packet_dns_txid(ctx, &dns_txid)) {
        LOG_PACKET("DNS hijack: malformed DNS payload, passing through");
        traffic_action_pass(action, ctx, addr, "DNS malformed pass");
        return;
    }

    if (engine->dns_hijack->use_socket_fwd) {
        traffic_dns_forward_t forward;
        forward.src_port = ctx->src_port;
        forward.original_dns_ip = ctx->dst_ip;
        forward.original_dns_port = ctx->dst_port;
        forward.client_ip = ctx->src_ip;
        forward.if_idx = addr->Network.IfIdx;
        forward.sub_if_idx = addr->Network.SubIfIdx;
        traffic_action_forward_dns(action, ctx, addr, &forward, "DNS socket forward");
        return;
    }

    uint32_t new_dst_ip = ctx->dst_ip;
    uint16_t new_dst_port = ctx->dst_port;
    if (dns_hijack_rewrite_request(engine->dns_hijack, &new_dst_ip, &new_dst_port,
                                    ctx->src_port, dns_txid,
                                    ctx->dst_ip, ctx->dst_port,
                                    ctx->src_ip, addr->Network.IfIdx, addr->Network.SubIfIdx) == 1) {
        ctx->ip_hdr->DstAddr = new_dst_ip;
        ctx->udp_hdr->DstPort = htons(new_dst_port);
        traffic_action_rewrite_send(action, ctx, addr, "DNS hijack");
    } else {
        LOG_WARN("DNS hijack: failed to store NAT entry, passing original query");
        traffic_action_pass(action, ctx, addr, "DNS hijack fallback");
    }
}

void dns_plan_tcp_query(divert_engine_t *engine, packet_ctx_t *ctx,
                        WINDIVERT_ADDRESS *addr, traffic_action_t *action) {
    char orig_str[16], redir_str[16];
    error_t err;

    err = conntrack_add_key_full(engine->conntrack,
                                 ctx->src_ip, ctx->src_port,
                                 engine->dns_hijack->redirect_ip, engine->dns_hijack->redirect_port,
                                 ctx->src_ip, ctx->src_port,
                                 ctx->dst_ip, ctx->dst_port,
                                 engine->dns_hijack->redirect_ip, engine->dns_hijack->redirect_port,
                                 6, 0, "",
                                 addr->Network.IfIdx, addr->Network.SubIfIdx,
                                 ctx->src_port);
    if (err != ERR_OK) {
        LOG_WARN("TCP DNS hijack: conntrack unavailable, dropping");
        traffic_action_drop(action, ctx, addr, "TCP DNS conntrack unavailable");
        return;
    }

    ctx->ip_hdr->DstAddr = engine->dns_hijack->redirect_ip;
    ctx->tcp_hdr->DstPort = htons(engine->dns_hijack->redirect_port);
    if (engine->dns_hijack->redirect_ip == LOOPBACK_ADDR) {
        divert_set_loopback_route(engine, addr);
    }

    ip_to_str(ctx->dst_ip, orig_str, sizeof(orig_str));
    ip_to_str(engine->dns_hijack->redirect_ip, redir_str, sizeof(redir_str));
    LOG_PACKET("TCP DNS hijack: %s:%u -> %s:%u", orig_str, ctx->dst_port,
        redir_str, engine->dns_hijack->redirect_port);
    traffic_action_rewrite_send(action, ctx, addr, "TCP DNS hijack");
}
