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

static void log_dns_query(const packet_observation_t *obs, int tcp_framed,
                          uint32_t orig_ip, uint16_t orig_port,
                          uint32_t target_ip, uint16_t target_port,
                          const char *action, const char *outcome,
                          int log_without_summary) {
    packet_dns_query_summary_t summary;
    char c[16], o[16], t[16], f[384];

    if (!log_is_enabled(LOG_TRACE)) return;

    if (!packet_dns_query_summary_observed(obs, tcp_framed, &summary)) {
        if (!log_without_summary) return;
        memset(&summary, 0, sizeof(summary));
    }
    ip_to_str(obs->src_ip, c, sizeof(c));
    ip_to_str(orig_ip, o, sizeof(o));
    ip_to_str(target_ip, t, sizeof(t));
    dns_format_query_fields(&summary, f, sizeof(f));
    LOG_TRACE("DNS %s query: client=%s:%u original=%s:%u target=%s:%u %s "
              "action=%s outcome=%s",
              tcp_framed ? "TCP" : "UDP",
              c, obs->src_port, o, orig_port, t, target_port,
              f, action ? action : "?", outcome ? outcome : "?");
}

void dns_plan_inbound_or_response(ndisapi_engine_t *engine,
                                  const packet_observation_t *obs,
                                  int is_dns_response, traffic_action_t *action) {
    if (is_dns_response) {
        uint32_t orig_ip;
        uint16_t orig_port;
        uint16_t txid;

        if (packet_dns_txid_observed(obs, &txid) &&
            dns_hijack_rewrite_response(engine->dns_hijack, &orig_ip, &orig_port,
                                         obs->dst_port, txid)) {
            traffic_action_rewrite_send_observed(action, obs, "dns response");
            traffic_action_rewrite_ip_src(action, orig_ip);
            traffic_action_rewrite_udp_sport(action, orig_port);
            traffic_action_set_send_target(action, TRAFFIC_SEND_TO_MSTCP);
            return;
        }
    }
    traffic_action_pass_observed(action, obs, "inbound");
}

void dns_plan_tcp_return(ndisapi_engine_t *engine,
                         const packet_observation_t *obs,
                         traffic_action_t *action) {
    conntrack_entry_t entry;

    if (conntrack_get_tcp_dns_return(engine->conntrack,
                                     obs->src_ip, obs->src_port,
                                     obs->dst_ip, obs->dst_port,
                                     &entry) != ERR_OK) {
        LOG_TRACE("TCP DNS return: no conntrack for port %u", obs->dst_port);
        traffic_action_drop_observed(action, obs, "tcp dns return missing");
        return;
    }
    traffic_action_rewrite_send_observed(action, obs, "tcp dns return");
    traffic_action_rewrite_ip_src(action, entry.orig_dst_ip);
    traffic_action_rewrite_ip_dst(action, entry.src_ip);
    traffic_action_rewrite_tcp_sport(action, entry.orig_dst_port);
    traffic_action_rewrite_tcp_dport(action, entry.client_port);
    traffic_action_rewrite_swap_eth(action);
    traffic_action_rewrite_clamp_tcp_mss(action, WTP_TCP_MSS_CLAMP);
    traffic_action_set_send_target(action, TRAFFIC_SEND_TO_MSTCP);
}

void dns_plan_udp_query(ndisapi_engine_t *engine,
                        const packet_observation_t *obs,
                        traffic_action_t *action) {
    const uint8_t *d;
    UINT dl;
    uint16_t txid = 0;

    packet_payload_observed(obs, &d, &dl);
    if (!d || dl < 2 || !packet_dns_txid_observed(obs, &txid)) {
        log_dns_query(obs, 0, obs->dst_ip, obs->dst_port,
                      obs->dst_ip, obs->dst_port, "pass", "malformed", 1);
        traffic_action_pass_observed(action, obs, "dns malformed");
        return;
    }

    if (engine->dns_hijack->use_socket_fwd) {
        traffic_dns_forward_t fw;

        log_dns_query(obs, 0, obs->dst_ip, obs->dst_port,
                      engine->dns_hijack->redirect_ip,
                      engine->dns_hijack->redirect_port,
                      "socket-forward", "queued", 1);

        fw.src_port = obs->src_port;
        fw.original_dns_ip = obs->dst_ip;
        fw.original_dns_port = obs->dst_port;
        fw.client_ip = obs->src_ip;
        fw.adapter_handle = obs->adapter_handle;
        traffic_action_forward_dns_observed(action, obs, &fw, "dns fwd");
        return;
    }

    {
        uint32_t nip = obs->dst_ip;
        uint16_t nport = obs->dst_port;

        if (dns_hijack_rewrite_request(engine->dns_hijack, &nip, &nport,
                                        obs->src_port, txid,
                                        obs->dst_ip, obs->dst_port,
                                        obs->src_ip,
                                        obs->adapter_handle) == 1) {
            log_dns_query(obs, 0, obs->dst_ip, obs->dst_port, nip, nport,
                          "rewrite", "ok", 1);
            traffic_action_rewrite_send_observed(action, obs, "dns hijack");
            traffic_action_rewrite_ip_dst(action, nip);
            traffic_action_rewrite_udp_dport(action, nport);
        } else {
            LOG_WARN("DNS hijack: NAT store failed");
            traffic_action_pass_observed(action, obs, "dns fallback");
        }
    }
}

void dns_plan_tcp_query(ndisapi_engine_t *engine,
                        const packet_observation_t *obs,
                        traffic_action_t *action) {
    uint32_t odip = obs->dst_ip;
    uint32_t odport = obs->dst_port;
    uint32_t ifi = 0;
    conntrack_tcp_dns_flow_t flow;
    error_t err;

    if (obs->ndis_buf) {
        ifi = (uint32_t)(uintptr_t)obs->adapter_handle;
    }

    memset(&flow, 0, sizeof(flow));
    flow.client_ip = obs->src_ip;
    flow.client_port = obs->src_port;
    flow.original_dns_ip = obs->dst_ip;
    flow.original_dns_port = obs->dst_port;
    flow.redirect_ip = engine->dns_hijack->redirect_ip;
    flow.redirect_port = engine->dns_hijack->redirect_port;
    flow.loopback_redirect = engine->dns_hijack->redirect_ip == LOOPBACK_ADDR;
    flow.if_idx = ifi;

    err = conntrack_track_tcp_dns(engine->conntrack, &flow);
    if (err != ERR_OK) {
        LOG_WARN("TCP DNS: conntrack unavailable");
        traffic_action_drop_observed(action, obs, "tcp dns conntrack");
        return;
    }

    traffic_action_rewrite_send_observed(action, obs, "tcp dns hijack");
    traffic_action_rewrite_ip_dst(action, engine->dns_hijack->redirect_ip);
    traffic_action_rewrite_tcp_dport(action, engine->dns_hijack->redirect_port);
    if (engine->dns_hijack->redirect_ip == LOOPBACK_ADDR) {
        traffic_action_rewrite_ip_src(action, odip);
        traffic_action_rewrite_swap_eth(action);
        traffic_action_set_send_target(action, TRAFFIC_SEND_TO_MSTCP);
    }

    log_dns_query(obs, 1, odip, odport,
                  engine->dns_hijack->redirect_ip,
                  engine->dns_hijack->redirect_port,
                  "rewrite", "ok", 0);
}
