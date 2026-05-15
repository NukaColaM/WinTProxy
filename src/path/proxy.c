#include "path/proxy.h"
#include "divert/io.h"
#include "policy/rules.h"
#include "app/log.h"
#include "core/util.h"
#include <stdio.h>
#include <winsock2.h>

static error_t add_proxy_conntrack(divert_engine_t *engine, packet_ctx_t *ctx,
                                   WINDIVERT_ADDRESS *addr, uint32_t pid,
                                   const char *proc_name) {
    conntrack_entry_t existing;
    uint16_t relay_src_port = ctx->src_port;
    uint32_t relay_dst_ip = ctx->dst_ip;
    uint16_t relay_dst_port = ctx->dst_port;
    error_t err = ERR_OK;

    if (ctx->tcp_hdr) {
        if (conntrack_get_full_key(engine->conntrack,
                                   ctx->src_ip, ctx->src_port,
                                   relay_dst_ip, relay_dst_port,
                                   ctx->protocol, &existing) == ERR_OK &&
            existing.relay_src_port != 0) {
            relay_src_port = existing.relay_src_port;
        } else {
            relay_src_port = divert_next_tcp_relay_src_port(engine);
        }

        err = conntrack_add_key_full(engine->conntrack,
                                     ctx->src_ip, ctx->src_port,
                                     relay_dst_ip, relay_dst_port,
                                     ctx->src_ip, ctx->src_port,
                                     ctx->dst_ip, ctx->dst_port,
                                     relay_dst_ip, relay_dst_port,
                                     ctx->protocol, pid, proc_name,
                                     addr->Network.IfIdx, addr->Network.SubIfIdx,
                                     relay_src_port);
        if (err != ERR_OK) return err;

        err = conntrack_add_key_full(engine->conntrack,
                                     LOOPBACK_ADDR, relay_src_port,
                                     LOOPBACK_ADDR, engine->tcp_relay_port,
                                     ctx->src_ip, ctx->src_port,
                                     ctx->dst_ip, ctx->dst_port,
                                     relay_dst_ip, relay_dst_port,
                                     ctx->protocol, pid, proc_name,
                                     addr->Network.IfIdx, addr->Network.SubIfIdx,
                                     relay_src_port);
        if (err != ERR_OK) {
            conntrack_remove_key(engine->conntrack, ctx->src_ip, ctx->src_port,
                                 relay_dst_ip, relay_dst_port, ctx->protocol);
            return err;
        }

        if (conntrack_get_full_key(engine->conntrack,
                                   ctx->src_ip, ctx->src_port,
                                   relay_dst_ip, relay_dst_port,
                                   ctx->protocol, &existing) == ERR_OK &&
            existing.relay_src_port != 0 &&
            existing.relay_src_port != relay_src_port) {
            conntrack_remove_key(engine->conntrack, LOOPBACK_ADDR, relay_src_port,
                                 LOOPBACK_ADDR, engine->tcp_relay_port, ctx->protocol);
            relay_src_port = existing.relay_src_port;
        }

        ctx->tcp_hdr->SrcPort = htons(relay_src_port);
    } else if (ctx->udp_hdr) {
        err = conntrack_add(engine->conntrack, ctx->src_port, ctx->src_ip,
                            ctx->dst_ip, ctx->dst_port, ctx->protocol,
                            pid, proc_name,
                            addr->Network.IfIdx, addr->Network.SubIfIdx);
        if (err != ERR_OK) return err;

        err = conntrack_add_key(engine->conntrack, LOOPBACK_ADDR, ctx->src_port,
                                ctx->src_ip, ctx->dst_ip, ctx->dst_port,
                                ctx->protocol, pid, proc_name,
                                addr->Network.IfIdx, addr->Network.SubIfIdx);
        if (err != ERR_OK) {
            conntrack_remove(engine->conntrack, ctx->src_ip, ctx->src_port, ctx->protocol);
            return err;
        }
    }

    return err;
}

static int plan_tcp_non_syn_tracked(divert_engine_t *engine, packet_ctx_t *ctx,
                                    WINDIVERT_ADDRESS *addr, traffic_action_t *action) {
    conntrack_entry_t entry;

    if (conntrack_get_full_key(engine->conntrack, ctx->src_ip, ctx->src_port,
                               ctx->dst_ip, ctx->dst_port, 6, &entry) != ERR_OK)
        return 0;

    ctx->ip_hdr->SrcAddr = LOOPBACK_ADDR;
    ctx->ip_hdr->DstAddr = LOOPBACK_ADDR;
    ctx->tcp_hdr->SrcPort = htons(entry.relay_src_port);
    ctx->tcp_hdr->DstPort = htons(engine->tcp_relay_port);
    divert_set_loopback_route(engine, addr);
    traffic_action_rewrite_send(action, ctx, addr, "TCP tracked non-SYN");
    return 1;
}

static void plan_tcp_non_syn_untracked(divert_engine_t *engine, packet_ctx_t *ctx,
                                       WINDIVERT_ADDRESS *addr, traffic_action_t *action) {
    char proc_name[256] = {0};
    uint32_t pid;
    rule_decision_t decision;

    pid = proc_lookup_tcp_retry(engine->proc_lookup, ctx->src_ip, ctx->src_port,
                                proc_name, sizeof(proc_name));
    if (pid > 0 && proc_is_self(engine->proc_lookup, pid)) {
        traffic_action_pass(action, ctx, addr, "self pass");
        return;
    }

    decision = policy_rules_match(engine->config->policy.rules, engine->config->policy.rule_count,
                                  engine->config->policy.default_decision,
                                  proc_name, ctx->dst_ip, ctx->dst_port, ctx->protocol,
                                  NULL);

    if (decision == RULE_DECISION_DIRECT) {
        traffic_action_pass(action, ctx, addr, "TCP non-SYN direct");
        return;
    }

    /*
     * A proxied TCP packet without conntrack cannot be safely redirected:
     * there is no relay source port to map the return path. Passing it
     * through would leak that flow outside the proxy.
     */
    traffic_action_drop(action, ctx, addr, "TCP non-SYN proxy without conntrack");
}

void path_plan_policy(divert_engine_t *engine, packet_ctx_t *ctx,
                      WINDIVERT_ADDRESS *addr, traffic_action_t *action) {
    char proc_name[256] = {0};
    char dst_str[16];
    char rule_str[16];
    uint32_t pid = 0;
    int matched_rule_id = 0;

    if (ctx->tcp_hdr) {
        if (ctx->tcp_hdr->Syn && !ctx->tcp_hdr->Ack) {
            pid = proc_lookup_tcp(engine->proc_lookup, ctx->src_ip, ctx->src_port,
                                  proc_name, sizeof(proc_name));
        } else {
            if (plan_tcp_non_syn_tracked(engine, ctx, addr, action)) return;
            plan_tcp_non_syn_untracked(engine, ctx, addr, action);
            return;
        }
    } else {
        pid = proc_lookup_udp(engine->proc_lookup, ctx->src_ip, ctx->src_port,
                              proc_name, sizeof(proc_name));
    }

    if (pid > 0 && proc_is_self(engine->proc_lookup, pid)) {
        LOG_DEBUG("SELF: pid=%u %s, passing through", pid, proc_name);
        traffic_action_pass(action, ctx, addr, "self pass");
        return;
    }

    ip_to_str(ctx->dst_ip, dst_str, sizeof(dst_str));

    if (pid == 0) {
        if (ctx->tcp_hdr) {
            pid = proc_lookup_tcp_retry(engine->proc_lookup, ctx->src_ip, ctx->src_port,
                                        proc_name, sizeof(proc_name));
        } else {
            pid = proc_lookup_udp_retry(engine->proc_lookup, ctx->src_ip, ctx->src_port,
                                        proc_name, sizeof(proc_name));
        }
        if (pid > 0 && proc_is_self(engine->proc_lookup, pid)) {
            LOG_DEBUG("SELF: pid=%u %s, passing through", pid, proc_name);
            traffic_action_pass(action, ctx, addr, "self pass");
            return;
        }
    }

    rule_decision_t decision =
        policy_rules_match(engine->config->policy.rules, engine->config->policy.rule_count,
                           engine->config->policy.default_decision,
                           proc_name, ctx->dst_ip, ctx->dst_port, ctx->protocol,
                           &matched_rule_id);
    if (matched_rule_id > 0) snprintf(rule_str, sizeof(rule_str), "#%d", matched_rule_id);
    else safe_str_copy(rule_str, sizeof(rule_str), "default");

    if (decision == RULE_DECISION_DIRECT) {
        LOG_DEBUG("DIRECT: rule=%s %s [%u] -> %s:%u (%s)",
            rule_str, proc_name[0] ? proc_name : "?", pid, dst_str, ctx->dst_port,
            ctx->protocol == 6 ? "TCP" : "UDP");
        traffic_action_pass(action, ctx, addr, "direct");
        return;
    }

    uint16_t relay_port = (ctx->protocol == 6) ? engine->tcp_relay_port : engine->udp_relay_port;
    LOG_DEBUG("PROXY: rule=%s %s [%u] -> %s:%u via relay :%u (%s) IfIdx=%lu",
        rule_str, proc_name[0] ? proc_name : "?", pid, dst_str, ctx->dst_port, relay_port,
        ctx->protocol == 6 ? "TCP" : "UDP", (unsigned long)addr->Network.IfIdx);

    if (add_proxy_conntrack(engine, ctx, addr, pid, proc_name) != ERR_OK) {
        LOG_WARN("PROXY: conntrack unavailable for %s [%u] -> %s:%u (%s), dropping",
            proc_name[0] ? proc_name : "?", pid, dst_str, ctx->dst_port,
            ctx->protocol == 6 ? "TCP" : "UDP");
        traffic_action_drop(action, ctx, addr, "proxy conntrack unavailable");
        return;
    }

    if (ctx->tcp_hdr) {
        packet_clamp_tcp_mss(ctx, WTP_TCP_MSS_CLAMP);
        ctx->ip_hdr->SrcAddr = LOOPBACK_ADDR;
        ctx->ip_hdr->DstAddr = LOOPBACK_ADDR;
        ctx->tcp_hdr->DstPort = htons(relay_port);
        divert_set_loopback_route(engine, addr);
        traffic_action_rewrite_send(action, ctx, addr, "TCP PROXY redirect");
    } else {
        traffic_action_forward_udp(action, ctx, addr, "UDP PROXY relay forward");
    }
}
