/*
 * Proxy / policy path — MSTCP revert model.
 *
 * TCP SYN packets: create conntrack, swap IP+Eth addresses, redirect
 * destination to relay port, set direction flag to ON_RECEIVE so the
 * batcher sends to MSTCP.  The OS delivers the connection to the relay.
 *
 * Non-SYN tracked TCP: same rewrite using existing conntrack state.
 * Untracked non-SYN TCP: dropped (can't safely redirect).
 */
#include "path/proxy.h"
#include "path/classify.h"
#include "policy/rules.h"
#include "app/log.h"
#include "core/util.h"
#include <stdio.h>
#include <winsock2.h>

static error_t add_proxy_conntrack(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                                   uint32_t pid, const char *proc_name) {
    conntrack_entry_t existing;
    uint16_t relay_src_port = ctx->src_port;
    uint32_t server_ip  = ctx->dst_ip;
    uint16_t server_port = ctx->dst_port;
    uint32_t client_ip   = ctx->src_ip;
    error_t err = ERR_OK;
    uint32_t if_idx = 0, sub_if_idx = 0;

    /* Store adapter handle as if_idx for potential future use */
    if (ctx->ndis_buf) {
        if_idx = (uint32_t)(uintptr_t)ctx->ndis_buf->m_hAdapter;
    }

    if (ctx->tcp_hdr) {
        if (conntrack_get_full_key(engine->conntrack,
                                   client_ip, ctx->src_port,
                                   server_ip, server_port,
                                   ctx->protocol, &existing) == ERR_OK &&
            existing.relay_src_port != 0) {
            relay_src_port = existing.relay_src_port;
        } else {
            relay_src_port = ndisapi_next_tcp_relay_src_port(engine);
        }

        /* Entry A: (client_ip, client_port, server_ip, server_port) */
        err = conntrack_add_key_full(engine->conntrack,
                                     client_ip, ctx->src_port,
                                     server_ip, server_port,
                                     client_ip, ctx->src_port,
                                     server_ip, server_port,
                                     server_ip, server_port,
                                     ctx->protocol, pid, proc_name,
                                     if_idx, sub_if_idx,
                                     relay_src_port);
        if (err != ERR_OK) return err;

        /* Entry B: (server_ip, relay_src_port, client_ip, relay_port)
         *         — used by relay lookup and return path */
        err = conntrack_add_key_full(engine->conntrack,
                                     server_ip, relay_src_port,
                                     client_ip, engine->tcp_relay_port,
                                     client_ip, ctx->src_port,
                                     server_ip, server_port,
                                     server_ip, server_port,
                                     ctx->protocol, pid, proc_name,
                                     if_idx, sub_if_idx,
                                     relay_src_port);
        if (err != ERR_OK) {
            conntrack_remove_key(engine->conntrack, client_ip, ctx->src_port,
                                 server_ip, server_port, ctx->protocol);
            return err;
        }

        /* Handle race: another thread may have created an entry for the same
         * client tuple with a different relay_src_port.  Use whichever one
         * was created first (stored in existing.relay_src_port). */
        if (conntrack_get_full_key(engine->conntrack,
                                   client_ip, ctx->src_port,
                                   server_ip, server_port,
                                   ctx->protocol, &existing) == ERR_OK &&
            existing.relay_src_port != 0 &&
            existing.relay_src_port != relay_src_port) {
            conntrack_remove_key(engine->conntrack, server_ip, relay_src_port,
                                 client_ip, engine->tcp_relay_port,
                                 ctx->protocol);
            relay_src_port = existing.relay_src_port;
        }

        /* Update the TCP source port in the packet to relay_src_port */
        ctx->tcp_hdr->th_sport = htons(relay_src_port);
    } else if (ctx->udp_hdr) {
        err = conntrack_add(engine->conntrack, ctx->src_port, client_ip,
                            server_ip, server_port, ctx->protocol,
                            pid, proc_name, if_idx, sub_if_idx);
        if (err != ERR_OK) return err;

        err = conntrack_add_key(engine->conntrack, server_ip, ctx->src_port,
                                client_ip, server_ip, server_port,
                                ctx->protocol, pid, proc_name,
                                if_idx, sub_if_idx);
        if (err != ERR_OK) {
            conntrack_remove(engine->conntrack, client_ip, ctx->src_port,
                             ctx->protocol);
            return err;
        }
    }

    return err;
}

/*
 * Non-SYN tracked TCP: redirect to relay using existing conntrack state.
 */
static int plan_tcp_non_syn_tracked(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                                    traffic_action_t *action) {
    conntrack_entry_t entry;

    if (conntrack_get_full_key(engine->conntrack, ctx->src_ip, ctx->src_port,
                               ctx->dst_ip, ctx->dst_port, WTP_IPPROTO_TCP, &entry) != ERR_OK)
        return 0;

    /* Swap IPs: client→server becomes server→client */
    ctx->ip_hdr->ip_src  = ctx->dst_ip;    /* server */
    ctx->ip_hdr->ip_dst  = entry.src_ip;   /* client */
    ctx->tcp_hdr->th_sport = htons(entry.relay_src_port);
    ctx->tcp_hdr->th_dport = htons(engine->tcp_relay_port);

    /* Swap Ethernet addresses */
    swap_ether_addrs(ctx->eth_hdr);

    /* Deliver to MSTCP (revert: ON_SEND → up the stack) */
    ctx->ndis_buf->m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;

    traffic_action_rewrite_send(action, ctx, ctx->ndis_buf,
                                "TCP tracked non-SYN");
    return 1;
}

static void plan_tcp_non_syn_untracked(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                                       traffic_action_t *action) {
    char proc_name[256] = {0};
    uint32_t pid;
    rule_decision_t decision;

    pid = proc_lookup_tcp_retry(engine->proc_lookup, ctx->src_ip, ctx->src_port,
                                proc_name, sizeof(proc_name));
    if (pid > 0 && proc_is_self(engine->proc_lookup, pid)) {
        traffic_action_pass(action, ctx, ctx->ndis_buf, "self pass");
        return;
    }

    decision = policy_rules_match(engine->config->policy.rules,
                                  engine->config->policy.rule_count,
                                  engine->config->policy.default_decision,
                                  proc_name, ctx->dst_ip, ctx->dst_port,
                                  ctx->protocol, NULL);

    if (decision == RULE_DECISION_DIRECT) {
        traffic_action_pass(action, ctx, ctx->ndis_buf, "TCP non-SYN direct");
        return;
    }

    traffic_action_drop(action, ctx, ctx->ndis_buf,
                        "TCP non-SYN proxy without conntrack");
}

void path_plan_policy(ndisapi_engine_t *engine, packet_ctx_t *ctx,
                      traffic_action_t *action) {
    char proc_name[256] = {0};
    char dst_str[16];
    char rule_str[16];
    uint32_t pid = 0;
    int matched_rule_id = 0;

    if (ctx->tcp_hdr) {
        if (ctx->tcp_hdr->th_flags & TH_SYN &&
            !(ctx->tcp_hdr->th_flags & TH_ACK)) {
            pid = proc_lookup_tcp(engine->proc_lookup, ctx->src_ip,
                                  ctx->src_port, proc_name, sizeof(proc_name));
        } else {
            if (plan_tcp_non_syn_tracked(engine, ctx, action)) return;
            plan_tcp_non_syn_untracked(engine, ctx, action);
            return;
        }
    } else {
        pid = proc_lookup_udp(engine->proc_lookup, ctx->src_ip,
                              ctx->src_port, proc_name, sizeof(proc_name));
    }

    if (pid > 0 && proc_is_self(engine->proc_lookup, pid)) {
        LOG_TRACE("SELF: pid=%u %s, passing through", pid, proc_name);
        traffic_action_pass(action, ctx, ctx->ndis_buf, "self pass");
        return;
    }

    ip_to_str(ctx->dst_ip, dst_str, sizeof(dst_str));

    if (pid == 0) {
        if (ctx->tcp_hdr) {
            pid = proc_lookup_tcp_retry(engine->proc_lookup, ctx->src_ip,
                                        ctx->src_port, proc_name,
                                        sizeof(proc_name));
        } else {
            pid = proc_lookup_udp_retry(engine->proc_lookup, ctx->src_ip,
                                        ctx->src_port, proc_name,
                                        sizeof(proc_name));
        }
        if (pid > 0 && proc_is_self(engine->proc_lookup, pid)) {
            LOG_TRACE("SELF: pid=%u %s, passing through", pid, proc_name);
            traffic_action_pass(action, ctx, ctx->ndis_buf, "self pass");
            return;
        }
    }

    rule_decision_t decision =
        policy_rules_match(engine->config->policy.rules,
                           engine->config->policy.rule_count,
                           engine->config->policy.default_decision,
                           proc_name, ctx->dst_ip, ctx->dst_port,
                           ctx->protocol, &matched_rule_id);
    if (matched_rule_id > 0)
        snprintf(rule_str, sizeof(rule_str), "#%d", matched_rule_id);
    else
        safe_str_copy(rule_str, sizeof(rule_str), "default");

    if (decision == RULE_DECISION_DIRECT) {
        LOG_TRACE("DIRECT: rule=%s %s [%u] -> %s:%u (%s)",
            rule_str, proc_name[0] ? proc_name : "?", pid,
            dst_str, ctx->dst_port,
            ctx->protocol == 6 ? "TCP" : "UDP");
        traffic_action_pass(action, ctx, ctx->ndis_buf, "direct");
        return;
    }

    uint16_t relay_port = (ctx->protocol == WTP_IPPROTO_TCP) ?
        engine->tcp_relay_port : engine->udp_relay_port;
    LOG_TRACE("PROXY: rule=%s %s [%u] -> %s:%u via relay :%u (%s)",
        rule_str, proc_name[0] ? proc_name : "?", pid,
        dst_str, ctx->dst_port, relay_port,
        ctx->protocol == 6 ? "TCP" : "UDP");

    if (add_proxy_conntrack(engine, ctx, pid, proc_name) != ERR_OK) {
        LOG_WARN("PROXY: conntrack unavailable for %s [%u] -> %s:%u (%s), "
                 "dropping",
            proc_name[0] ? proc_name : "?", pid, dst_str, ctx->dst_port,
            ctx->protocol == 6 ? "TCP" : "UDP");
        traffic_action_drop(action, ctx, ctx->ndis_buf,
                            "proxy conntrack unavailable");
        return;
    }

    /* New connection established — log at debug */
    if (ctx->tcp_hdr && (ctx->tcp_hdr->th_flags & TH_SYN)) {
        LOG_DEBUG("NEW PROXY: rule=%s %s [%u] -> %s:%u",
                  rule_str, proc_name[0] ? proc_name : "?", pid,
                  dst_str, ctx->dst_port);
    }

    if (ctx->tcp_hdr) {
        packet_clamp_tcp_mss(ctx, WTP_TCP_MSS_CLAMP);

        /* Swap IP addresses: client→server becomes server→client */
        ctx->ip_hdr->ip_src = ctx->dst_ip;   /* original server */
        ctx->ip_hdr->ip_dst = ctx->src_ip;   /* original client */
        ctx->tcp_hdr->th_dport = htons(relay_port);
        /* th_sport already set to relay_src_port by add_proxy_conntrack */

        /* Swap Ethernet MACs */
        swap_ether_addrs(ctx->eth_hdr);

        /* Revert: deliver to MSTCP instead of adapter */
        ctx->ndis_buf->m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;

        {
            char sip[16], dip[16];
            ip_to_str(ctx->ip_hdr->ip_src, sip, sizeof(sip));
            ip_to_str(ctx->ip_hdr->ip_dst, dip, sizeof(dip));
            LOG_TRACE("MSTCP inject: %s:%u -> %s:%u SYN=%d ACK=%d",
                      sip, ntohs(ctx->tcp_hdr->th_sport),
                      dip, ntohs(ctx->tcp_hdr->th_dport),
                      (ctx->tcp_hdr->th_flags & TH_SYN) ? 1 : 0,
                      (ctx->tcp_hdr->th_flags & TH_ACK) ? 1 : 0);
        }

        traffic_action_rewrite_send(action, ctx, ctx->ndis_buf,
                                    "TCP PROXY redirect");
    } else {
        /* UDP: forward to relay (unchanged T4) */
        traffic_action_forward_udp(action, ctx, ctx->ndis_buf,
                                   "UDP PROXY relay forward");
    }
}
