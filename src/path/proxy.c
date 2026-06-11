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
#include <string.h>
#include <winsock2.h>

static error_t add_proxy_conntrack(ndisapi_engine_t *engine,
                                   const packet_observation_t *obs,
                                   uint32_t pid, const char *proc_name,
                                   uint16_t *relay_src_port_out) {
    uint32_t if_idx = 0, sub_if_idx = 0;

    /* Store adapter handle as if_idx for potential future use */
    if (obs->ndis_buf) {
        if_idx = (uint32_t)(uintptr_t)obs->adapter_handle;
    }

    if (obs->has_tcp) {
        conntrack_tcp_proxy_flow_t flow;
        memset(&flow, 0, sizeof(flow));
        flow.client_ip = obs->src_ip;
        flow.client_port = obs->src_port;
        flow.server_ip = obs->dst_ip;
        flow.server_port = obs->dst_port;
        flow.relay_port = engine->tcp_relay_port;
        flow.proposed_relay_src_port = ndisapi_next_tcp_relay_src_port(engine);
        flow.pid = pid;
        flow.process_name = proc_name;
        flow.if_idx = if_idx;
        flow.sub_if_idx = sub_if_idx;
        return conntrack_track_tcp_proxy(engine->conntrack, &flow,
                                         relay_src_port_out);
    } else if (obs->has_udp) {
        conntrack_udp_proxy_flow_t flow;
        memset(&flow, 0, sizeof(flow));
        flow.client_ip = obs->src_ip;
        flow.client_port = obs->src_port;
        flow.server_ip = obs->dst_ip;
        flow.server_port = obs->dst_port;
        flow.pid = pid;
        flow.process_name = proc_name;
        flow.if_idx = if_idx;
        flow.sub_if_idx = sub_if_idx;
        if (relay_src_port_out) *relay_src_port_out = obs->src_port;
        return conntrack_track_udp_proxy(engine->conntrack, &flow);
    }

    return ERR_PARAM;
}

/*
 * Non-SYN tracked TCP: redirect to relay using existing conntrack state.
 */
static int plan_tcp_non_syn_tracked(ndisapi_engine_t *engine,
                                    const packet_observation_t *obs,
                                    traffic_action_t *action) {
    conntrack_entry_t entry;

    if (conntrack_get_tcp_proxy_outbound(engine->conntrack, obs->src_ip,
                                         obs->src_port, obs->dst_ip,
                                         obs->dst_port, &entry) != ERR_OK) {
        return 0;
    }

    if (entry.relay_src_port == 0) {
        conntrack_touch_direct_tcp(engine->conntrack, &entry);
        traffic_action_pass_observed(action, obs, "TCP tracked direct");
        return 1;
    }

    traffic_action_rewrite_send_observed(action, obs, "TCP tracked non-SYN");
    traffic_action_rewrite_ip_src(action, obs->dst_ip);
    traffic_action_rewrite_ip_dst(action, entry.src_ip);
    traffic_action_rewrite_tcp_sport(action, entry.relay_src_port);
    traffic_action_rewrite_tcp_dport(action, engine->tcp_relay_port);
    traffic_action_rewrite_swap_eth(action);
    traffic_action_rewrite_clamp_tcp_mss(action, WTP_TCP_MSS_CLAMP);
    traffic_action_set_send_target(action, TRAFFIC_SEND_TO_MSTCP);
    return 1;
}

static void plan_tcp_non_syn_untracked(ndisapi_engine_t *engine,
                                       const packet_observation_t *obs,
                                       traffic_action_t *action) {
    char proc_name[256] = {0};
    uint32_t pid;
    rule_decision_t decision;

    pid = proc_lookup_tcp_retry(engine->proc_lookup, obs->src_ip, obs->src_port,
                                proc_name, sizeof(proc_name));
    if (pid > 0 && proc_is_self(engine->proc_lookup, pid)) {
        traffic_action_pass_observed(action, obs, "self pass");
        return;
    }

    decision = policy_rules_match(engine->config->policy.rules,
                                  engine->config->policy.rule_count,
                                  engine->config->policy.default_decision,
                                  proc_name, obs->dst_ip, obs->dst_port,
                                  obs->protocol, NULL);

    if (decision == RULE_DECISION_DIRECT) {
        traffic_action_drop_observed(action, obs, "preexisting direct tcp");
        return;
    }

    traffic_action_drop_observed(action, obs,
                                 "TCP non-SYN proxy without conntrack");
}

void path_plan_policy(ndisapi_engine_t *engine,
                      const packet_observation_t *obs,
                      traffic_action_t *action) {
    char proc_name[256] = {0};
    char dst_str[16];
    char rule_str[16];
    uint32_t pid = 0;
    int matched_rule_id = 0;
    uint16_t relay_src_port = 0;

    if (obs->has_tcp) {
        if (obs->tcp_flags & TH_SYN &&
            !(obs->tcp_flags & TH_ACK)) {
            pid = proc_lookup_tcp(engine->proc_lookup, obs->src_ip,
                                  obs->src_port, proc_name, sizeof(proc_name));
        } else {
            if (plan_tcp_non_syn_tracked(engine, obs, action)) return;
            plan_tcp_non_syn_untracked(engine, obs, action);
            return;
        }
    } else {
        pid = proc_lookup_udp(engine->proc_lookup, obs->src_ip,
                              obs->src_port, proc_name, sizeof(proc_name));
    }

    if (pid > 0 && proc_is_self(engine->proc_lookup, pid)) {
        LOG_TRACE("SELF: pid=%u %s, passing through", pid, proc_name);
        traffic_action_pass_observed(action, obs, "self pass");
        return;
    }

    ip_to_str(obs->dst_ip, dst_str, sizeof(dst_str));

    if (pid == 0) {
        if (obs->has_tcp) {
            pid = proc_lookup_tcp_retry(engine->proc_lookup, obs->src_ip,
                                        obs->src_port, proc_name,
                                        sizeof(proc_name));
        } else {
            pid = proc_lookup_udp_retry(engine->proc_lookup, obs->src_ip,
                                        obs->src_port, proc_name,
                                        sizeof(proc_name));
        }
        if (pid > 0 && proc_is_self(engine->proc_lookup, pid)) {
            LOG_TRACE("SELF: pid=%u %s, passing through", pid, proc_name);
            traffic_action_pass_observed(action, obs, "self pass");
            return;
        }
    }

    rule_decision_t decision =
        policy_rules_match(engine->config->policy.rules,
                           engine->config->policy.rule_count,
                           engine->config->policy.default_decision,
                           proc_name, obs->dst_ip, obs->dst_port,
                           obs->protocol, &matched_rule_id);
    if (matched_rule_id > 0)
        snprintf(rule_str, sizeof(rule_str), "#%d", matched_rule_id);
    else
        safe_str_copy(rule_str, sizeof(rule_str), "default");

    if (decision == RULE_DECISION_DIRECT) {
        LOG_DEBUG("DIRECT: rule=%s %s [%u] -> %s:%u (%s)",
            rule_str, proc_name[0] ? proc_name : "?", pid,
            dst_str, obs->dst_port,
            obs->protocol == 6 ? "TCP" : "UDP");
        if (obs->has_tcp) {
            uint32_t if_idx = 0;
            conntrack_direct_tcp_flow_t flow;
            if (obs->ndis_buf) {
                if_idx = (uint32_t)(uintptr_t)obs->adapter_handle;
            }
            memset(&flow, 0, sizeof(flow));
            flow.client_ip = obs->src_ip;
            flow.client_port = obs->src_port;
            flow.server_ip = obs->dst_ip;
            flow.server_port = obs->dst_port;
            flow.pid = pid;
            flow.process_name = proc_name;
            flow.if_idx = if_idx;
            if (conntrack_track_direct_tcp(engine->conntrack, &flow) != ERR_OK) {
                LOG_WARN("DIRECT: conntrack unavailable for %s [%u] -> %s:%u "
                         "(%s), dropping",
                         proc_name[0] ? proc_name : "?", pid,
                         dst_str, obs->dst_port,
                         obs->protocol == 6 ? "TCP" : "UDP");
                traffic_action_drop_observed(action, obs,
                                             "direct conntrack unavailable");
                return;
            }
        }
        traffic_action_pass_observed(action, obs, "direct");
        return;
    }

    uint16_t relay_port = (obs->protocol == WTP_IPPROTO_TCP) ?
        engine->tcp_relay_port : engine->udp_relay_port;
    LOG_DEBUG("PROXY: rule=%s %s [%u] -> %s:%u via relay :%u (%s)",
        rule_str, proc_name[0] ? proc_name : "?", pid,
        dst_str, obs->dst_port, relay_port,
        obs->protocol == 6 ? "TCP" : "UDP");

    if (add_proxy_conntrack(engine, obs, pid, proc_name, &relay_src_port) != ERR_OK) {
        LOG_WARN("PROXY: conntrack unavailable for %s [%u] -> %s:%u (%s), "
                 "dropping",
            proc_name[0] ? proc_name : "?", pid, dst_str, obs->dst_port,
            obs->protocol == 6 ? "TCP" : "UDP");
        traffic_action_drop_observed(action, obs, "proxy conntrack unavailable");
        return;
    }

    /* New connection established — log at debug */
    if (obs->has_tcp && (obs->tcp_flags & TH_SYN)) {
        LOG_DEBUG("NEW PROXY: rule=%s %s [%u] -> %s:%u",
                  rule_str, proc_name[0] ? proc_name : "?", pid,
                  dst_str, obs->dst_port);
    }

    if (obs->has_tcp) {
        traffic_action_rewrite_send_observed(action, obs, "TCP PROXY redirect");
        traffic_action_rewrite_ip_src(action, obs->dst_ip);
        traffic_action_rewrite_ip_dst(action, obs->src_ip);
        traffic_action_rewrite_tcp_sport(action, relay_src_port);
        traffic_action_rewrite_tcp_dport(action, relay_port);
        traffic_action_rewrite_swap_eth(action);
        traffic_action_rewrite_clamp_tcp_mss(action, WTP_TCP_MSS_CLAMP);
        traffic_action_set_send_target(action, TRAFFIC_SEND_TO_MSTCP);
    } else {
        /* UDP: forward to relay (unchanged T4) */
        traffic_action_forward_udp_observed(action, obs,
                                            "UDP PROXY relay forward");
    }
}
