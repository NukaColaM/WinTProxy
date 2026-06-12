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

void path_plan_return(ndisapi_engine_t *engine,
                      const packet_observation_t *obs,
                      int is_tcp, traffic_action_t *action) {
    conntrack_role_snapshot_t snap;
    error_t err;

    /*
     * Fused role lookup: restores the original tuple and refreshes pair
     * liveness in the same conntrack pass - no separate touch calls.
     *
     * For TCP, the relay's response packet has:
     *   src = client_ip:relay_port  (relay bound to INADDR_ANY)
     *   dst = server_ip:relay_src_port
     * Entry B key: (server_ip, relay_src_port, client_ip, relay_port, TCP)
     * So we look up (obs->dst_ip, obs->dst_port, obs->src_ip, obs->src_port).
     */
    if (is_tcp) {
        err = conntrack_role_tcp_return(engine->conntrack,
                                        obs->dst_ip, obs->dst_port,
                                        obs->src_ip, obs->src_port,
                                        &snap);
    } else {
        err = conntrack_role_udp_return(engine->conntrack,
                                        obs->dst_ip, obs->dst_port,
                                        &snap);
    }
    if (err != ERR_OK) {
        LOG_WARN("%s return: no conntrack for dst %s:%u",
                 is_tcp ? "TCP" : "UDP",
                 is_tcp ? "?" : "",
                 obs ? obs->dst_port : 0);
        traffic_action_drop_observed(action, obs,
                                     is_tcp ? "TCP return missing conntrack"
                                            : "UDP return missing conntrack");
        return;
    }

    if (log_is_enabled(LOG_TRACE)) {
        char orig_dst_str[16], orig_src_str[16];
        ip_to_str(snap.orig_dst_ip, orig_dst_str, sizeof(orig_dst_str));
        ip_to_str(snap.client_ip, orig_src_str, sizeof(orig_src_str));
        LOG_TRACE("%s return: rewrite %s:%u -> %s:%u",
            is_tcp ? "TCP" : "UDP",
            orig_dst_str, snap.orig_dst_port,
            orig_src_str, snap.client_port);
    }

    traffic_action_rewrite_send_observed(action, obs,
                                         is_tcp ? "TCP return" : "UDP return");
    traffic_action_rewrite_ip_src(action, snap.orig_dst_ip);
    traffic_action_rewrite_ip_dst(action, snap.client_ip);
    if (is_tcp) {
        traffic_action_rewrite_tcp_sport(action, snap.orig_dst_port);
        traffic_action_rewrite_tcp_dport(action, snap.client_port);
        traffic_action_rewrite_clamp_tcp_mss(action, WTP_TCP_MSS_CLAMP);
    } else {
        traffic_action_rewrite_udp_sport(action, snap.orig_dst_port);
    }
    traffic_action_rewrite_swap_eth(action);
    traffic_action_set_send_target(action, TRAFFIC_SEND_TO_MSTCP);
}
