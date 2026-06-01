/*
 * DNS plan — UDP/TCP DNS intercept and redirection (full T5).
 */
#include "dns/plan.h"
#include "dns/hijack.h"
#include "path/classify.h"
#include "conntrack/conntrack.h"
#include "app/log.h"
#include "core/util.h"
#include <string.h>
#include <stdio.h>
#include <winsock2.h>

static const char *dns_qname_or_unknown(const packet_dns_query_summary_t *s) {
    return s->question_valid ? s->qname : "?";
}

static void dns_format_query_fields(const packet_dns_query_summary_t *s,
                                    char *buf, size_t len) {
    if (!buf || len == 0) return;
    if (!s || !s->txid_valid) {
        snprintf(buf, len, "txid=? qname=? qtype=? qclass=?");
    } else if (s->question_valid) {
        snprintf(buf, len, "txid=0x%04x qname=%s qtype=%u qclass=%u",
                 s->txid, dns_qname_or_unknown(s), s->qtype, s->qclass);
    } else {
        snprintf(buf, len, "txid=0x%04x qname=? qtype=? qclass=?", s->txid);
    }
}

static void log_dns_query(packet_ctx_t *ctx, int tcp_framed,
                          uint32_t orig_ip, uint16_t orig_port,
                          uint32_t target_ip, uint16_t target_port,
                          const char *action, const char *outcome,
                          int log_without_summary) {
    packet_dns_query_summary_t summary;
    char c[16], o[16], t[16], f[384];

    if (!log_is_enabled(LOG_TRACE)) return;

    if (!packet_dns_query_summary(ctx, tcp_framed, &summary)) {
        if (!log_without_summary) return;
        memset(&summary, 0, sizeof(summary));
    }
    ip_to_str(ctx->src_ip, c, sizeof(c));
    ip_to_str(orig_ip, o, sizeof(o));
    ip_to_str(target_ip, t, sizeof(t));
    dns_format_query_fields(&summary, f, sizeof(f));
    LOG_TRACE("DNS %s query: client=%s:%u original=%s:%u target=%s:%u %s "
              "action=%s outcome=%s",
              tcp_framed ? "TCP" : "UDP",
              c, ctx->src_port, o, orig_port, t, target_port,
              f, action ? action : "?", outcome ? outcome : "?");
}

void dns_plan_inbound_or_response(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                                  int is_dns_response, traffic_action_t *action) {
    if (is_dns_response) {
        uint32_t orig_ip;
        uint16_t orig_port;
        uint16_t txid;

        if (packet_dns_txid(ctx, &txid) &&
            dns_hijack_rewrite_response(engine->dns_hijack, &orig_ip, &orig_port,
                                         ctx->dst_port, txid)) {
            traffic_action_rewrite_send(action, ctx, ctx->ndis_buf, "dns response");
            traffic_action_rewrite_ip_src(action, orig_ip);
            traffic_action_rewrite_udp_sport(action, orig_port);
            traffic_action_set_send_target(action, TRAFFIC_SEND_TO_MSTCP);
            return;
        }
    }
    traffic_action_pass(action, ctx, ctx ? ctx->ndis_buf : NULL, "inbound");
}

void dns_plan_tcp_return(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                         traffic_action_t *action) {
    conntrack_entry_t entry;

    if (conntrack_get_full_key(engine->conntrack, ctx->dst_ip, ctx->dst_port,
                               ctx->src_ip, ctx->src_port, WTP_IPPROTO_TCP,
                               &entry) != ERR_OK) {
        LOG_TRACE("TCP DNS return: no conntrack for port %u", ctx->dst_port);
        traffic_action_drop(action, ctx, ctx->ndis_buf, "tcp dns return missing");
        return;
    }
    traffic_action_rewrite_send(action, ctx, ctx->ndis_buf, "tcp dns return");
    traffic_action_rewrite_ip_src(action, entry.orig_dst_ip);
    traffic_action_rewrite_ip_dst(action, entry.src_ip);
    traffic_action_rewrite_tcp_sport(action, entry.orig_dst_port);
    traffic_action_rewrite_tcp_dport(action, entry.client_port);
    traffic_action_rewrite_swap_eth(action);
    traffic_action_rewrite_clamp_tcp_mss(action, WTP_TCP_MSS_CLAMP);
    traffic_action_set_send_target(action, TRAFFIC_SEND_TO_MSTCP);
}

void dns_plan_udp_query(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                        traffic_action_t *action) {
    const uint8_t *d;
    UINT dl;
    uint16_t txid = 0;

    packet_payload(ctx, &d, &dl);
    if (!d || dl < 2 || !packet_dns_txid(ctx, &txid)) {
        log_dns_query(ctx, 0, ctx->dst_ip, ctx->dst_port,
                      ctx->dst_ip, ctx->dst_port, "pass", "malformed", 1);
        traffic_action_pass(action, ctx, ctx->ndis_buf, "dns malformed");
        return;
    }

    if (engine->dns_hijack->use_socket_fwd) {
        traffic_dns_forward_t fw;

        log_dns_query(ctx, 0, ctx->dst_ip, ctx->dst_port,
                      engine->dns_hijack->redirect_ip,
                      engine->dns_hijack->redirect_port,
                      "socket-forward", "queued", 1);

        fw.src_port = ctx->src_port;
        fw.original_dns_ip = ctx->dst_ip;
        fw.original_dns_port = ctx->dst_port;
        fw.client_ip = ctx->src_ip;
        fw.adapter_handle = ctx->ndis_buf->m_hAdapter;
        traffic_action_forward_dns(action, ctx, ctx->ndis_buf, &fw, "dns fwd");
        return;
    }

    {
        uint32_t nip = ctx->dst_ip;
        uint16_t nport = ctx->dst_port;

        if (dns_hijack_rewrite_request(engine->dns_hijack, &nip, &nport,
                                        ctx->src_port, txid,
                                        ctx->dst_ip, ctx->dst_port,
                                        ctx->src_ip,
                                        ctx->ndis_buf->m_hAdapter) == 1) {
            log_dns_query(ctx, 0, ctx->dst_ip, ctx->dst_port, nip, nport,
                          "rewrite", "ok", 1);
            traffic_action_rewrite_send(action, ctx, ctx->ndis_buf,
                                        "dns hijack");
            traffic_action_rewrite_ip_dst(action, nip);
            traffic_action_rewrite_udp_dport(action, nport);
        } else {
            LOG_WARN("DNS hijack: NAT store failed");
            traffic_action_pass(action, ctx, ctx->ndis_buf, "dns fallback");
        }
    }
}

void dns_plan_tcp_query(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                        traffic_action_t *action) {
    uint32_t odip = ctx->dst_ip;
    uint32_t odport = ctx->dst_port;
    uint32_t ksi = ctx->src_ip;
    uint32_t ifi = 0;
    error_t err;

    if (ctx->ndis_buf) {
        ifi = (uint32_t)(uintptr_t)ctx->ndis_buf->m_hAdapter;
    }

    if (engine->dns_hijack->redirect_ip == LOOPBACK_ADDR) {
        ksi = ctx->dst_ip; /* force response through adapter */
    }

    err = conntrack_add_key_full(engine->conntrack, ksi, ctx->src_port,
                                 engine->dns_hijack->redirect_ip,
                                 engine->dns_hijack->redirect_port,
                                 ctx->src_ip, ctx->src_port,
                                 ctx->dst_ip, ctx->dst_port,
                                 engine->dns_hijack->redirect_ip,
                                 engine->dns_hijack->redirect_port,
                                 WTP_IPPROTO_TCP, 0, "", ifi, 0,
                                 ctx->src_port);
    if (err != ERR_OK) {
        LOG_WARN("TCP DNS: conntrack unavailable");
        traffic_action_drop(action, ctx, ctx->ndis_buf,
                            "tcp dns conntrack");
        return;
    }

    traffic_action_rewrite_send(action, ctx, ctx->ndis_buf, "tcp dns hijack");
    traffic_action_rewrite_ip_dst(action, engine->dns_hijack->redirect_ip);
    traffic_action_rewrite_tcp_dport(action, engine->dns_hijack->redirect_port);
    if (engine->dns_hijack->redirect_ip == LOOPBACK_ADDR) {
        traffic_action_rewrite_ip_src(action, odip);
        traffic_action_rewrite_swap_eth(action);
        traffic_action_set_send_target(action, TRAFFIC_SEND_TO_MSTCP);
    }

    log_dns_query(ctx, 1, odip, odport,
                  engine->dns_hijack->redirect_ip,
                  engine->dns_hijack->redirect_port,
                  "rewrite", "ok", 0);
}
