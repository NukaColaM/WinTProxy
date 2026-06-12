#include <stdio.h>
#include <string.h>

#include "core/constants.h"
#include "core/util.h"
#include "dns/hijack.h"
#include "dns/plan.h"
#include "flow/action.h"
#include "flow/executor.h"
#include "flow/plan.h"
#include "ndisapi/adapter.h"
#include "net/headers.h"
#include "path/bypass.h"
#include "path/proxy.h"
#include "path/return.h"

extern int g_test_adapter_send_count;
extern int g_test_mstcp_send_count;
extern int g_test_adapter_send_call_count;
extern int g_test_mstcp_send_call_count;
extern INTERMEDIATE_BUFFER g_test_last_mstcp_packet;
extern int g_test_last_mstcp_packet_valid;
extern int g_test_mstcp_send_error;
extern int g_test_send_failure_count;
extern int g_test_drop_count;
extern int g_test_udp_forwarded_count;
extern int g_test_dns_forwarded_count;
extern int g_test_dns_forward_error;
extern int g_test_conntrack_get_full_key_hit;
extern int g_test_conntrack_tcp_proxy_outbound_hit;
extern int g_test_conntrack_tcp_proxy_return_hit;
extern int g_test_conntrack_role_tcp_outbound_count;
extern int g_test_conntrack_role_tcp_return_count;
extern int g_test_conntrack_role_tcp_dns_return_count;
extern int g_test_conntrack_role_refresh_tcp_pair_count;
extern int g_test_conntrack_udp_proxy_outbound_hit;
extern int g_test_conntrack_udp_proxy_return_hit;
extern int g_test_conntrack_role_udp_outbound_count;
extern int g_test_conntrack_role_udp_return_count;
extern int g_test_proc_lookup_tcp_count;
extern int g_test_proc_lookup_tcp_retry_count;
extern int g_test_proc_lookup_udp_count;
extern int g_test_proc_lookup_udp_retry_count;
extern uint32_t g_test_proc_lookup_tcp_pid;
extern uint32_t g_test_proc_self_pid;
extern int g_test_conntrack_raw_full_key_add_count;
extern int g_test_conntrack_direct_tcp_track_count;
extern int g_test_conntrack_tcp_proxy_track_count;
extern int g_test_conntrack_udp_proxy_track_count;
extern int g_test_conntrack_tcp_dns_track_count;
extern int g_test_dns_rewrite_request_hit;
extern uint32_t g_test_dns_rewrite_request_ip;
extern uint16_t g_test_dns_rewrite_request_port;
extern int g_test_dns_rewrite_response_hit;
extern uint32_t g_test_dns_rewrite_response_ip;
extern uint16_t g_test_dns_rewrite_response_port;
extern conntrack_entry_t g_test_conntrack_entry;
extern void test_reset_conntrack_stub_state(void);

static int failures = 0;

static void reset_counters(void) {
    g_test_adapter_send_count = 0;
    g_test_mstcp_send_count = 0;
    g_test_adapter_send_call_count = 0;
    g_test_mstcp_send_call_count = 0;
    memset(&g_test_last_mstcp_packet, 0, sizeof(g_test_last_mstcp_packet));
    g_test_last_mstcp_packet_valid = 0;
    g_test_mstcp_send_error = 0;
    g_test_send_failure_count = 0;
    g_test_drop_count = 0;
    g_test_udp_forwarded_count = 0;
    g_test_dns_forwarded_count = 0;
    g_test_dns_forward_error = 0;
    g_test_conntrack_get_full_key_hit = 0;
    g_test_conntrack_tcp_proxy_outbound_hit = 0;
    g_test_conntrack_tcp_proxy_return_hit = 0;
    g_test_conntrack_role_tcp_outbound_count = 0;
    g_test_conntrack_role_tcp_return_count = 0;
    g_test_conntrack_role_tcp_dns_return_count = 0;
    g_test_conntrack_role_refresh_tcp_pair_count = 0;
    g_test_conntrack_udp_proxy_outbound_hit = 0;
    g_test_conntrack_udp_proxy_return_hit = 0;
    g_test_conntrack_role_udp_outbound_count = 0;
    g_test_conntrack_role_udp_return_count = 0;
    g_test_proc_lookup_tcp_count = 0;
    g_test_proc_lookup_tcp_retry_count = 0;
    g_test_proc_lookup_udp_count = 0;
    g_test_proc_lookup_udp_retry_count = 0;
    g_test_proc_lookup_tcp_pid = 0;
    g_test_proc_self_pid = 0;
    g_test_conntrack_raw_full_key_add_count = 0;
    g_test_conntrack_direct_tcp_track_count = 0;
    g_test_conntrack_tcp_proxy_track_count = 0;
    g_test_conntrack_udp_proxy_track_count = 0;
    g_test_conntrack_tcp_dns_track_count = 0;
    g_test_dns_rewrite_request_hit = 0;
    g_test_dns_rewrite_request_ip = 0;
    g_test_dns_rewrite_request_port = 0;
    g_test_dns_rewrite_response_hit = 0;
    g_test_dns_rewrite_response_ip = 0;
    g_test_dns_rewrite_response_port = 0;
    memset(&g_test_conntrack_entry, 0, sizeof(g_test_conntrack_entry));
    test_reset_conntrack_stub_state();
}

static void init_engine(ndisapi_engine_t *engine, app_config_t *cfg,
                        dns_hijack_t *dns_hijack) {
    memset(engine, 0, sizeof(*engine));
    memset(cfg, 0, sizeof(*cfg));
    memset(dns_hijack, 0, sizeof(*dns_hijack));
    engine->config = cfg;
    engine->dns_hijack = dns_hijack;
}

static void check_int(const char *name, long got, long want) {
    if (got != want) {
        fprintf(stderr, "FAIL %s: got %ld want %ld\n", name, got, want);
        failures++;
    }
}

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    int has_tcp;
    int has_udp;
    uint8_t tcp_flags;
    int outbound;
    int inbound;
    const uint8_t *payload_data;
    UINT payload_len;
    int payload_valid;
    uint16_t dns_txid;
    int dns_txid_valid;
} observation_snapshot_t;

static observation_snapshot_t snapshot_observation(const packet_observation_t *obs) {
    observation_snapshot_t snap;

    memset(&snap, 0, sizeof(snap));
    if (!obs) return snap;

    snap.src_ip = obs->src_ip;
    snap.dst_ip = obs->dst_ip;
    snap.src_port = obs->src_port;
    snap.dst_port = obs->dst_port;
    snap.protocol = obs->protocol;
    snap.has_tcp = obs->has_tcp;
    snap.has_udp = obs->has_udp;
    snap.tcp_flags = obs->tcp_flags;
    snap.outbound = obs->outbound;
    snap.inbound = obs->inbound;
    snap.payload_data = obs->payload_data;
    snap.payload_len = obs->payload_len;
    snap.payload_valid = obs->payload_valid;
    snap.dns_txid = obs->dns_txid;
    snap.dns_txid_valid = obs->dns_txid_valid;
    return snap;
}

static void check_observation_snapshot(const char *label,
                                       const packet_observation_t *obs,
                                       const observation_snapshot_t *want) {
    char name[128];

    snprintf(name, sizeof(name), "%s src ip", label);
    check_int(name, (long)obs->src_ip, (long)want->src_ip);
    snprintf(name, sizeof(name), "%s dst ip", label);
    check_int(name, (long)obs->dst_ip, (long)want->dst_ip);
    snprintf(name, sizeof(name), "%s src port", label);
    check_int(name, obs->src_port, want->src_port);
    snprintf(name, sizeof(name), "%s dst port", label);
    check_int(name, obs->dst_port, want->dst_port);
    snprintf(name, sizeof(name), "%s protocol", label);
    check_int(name, obs->protocol, want->protocol);
    snprintf(name, sizeof(name), "%s has tcp", label);
    check_int(name, obs->has_tcp, want->has_tcp);
    snprintf(name, sizeof(name), "%s has udp", label);
    check_int(name, obs->has_udp, want->has_udp);
    snprintf(name, sizeof(name), "%s tcp flags", label);
    check_int(name, obs->tcp_flags, want->tcp_flags);
    snprintf(name, sizeof(name), "%s outbound", label);
    check_int(name, obs->outbound, want->outbound);
    snprintf(name, sizeof(name), "%s inbound", label);
    check_int(name, obs->inbound, want->inbound);
    snprintf(name, sizeof(name), "%s payload valid", label);
    check_int(name, obs->payload_valid, want->payload_valid);
    snprintf(name, sizeof(name), "%s payload len", label);
    check_int(name, (long)obs->payload_len, (long)want->payload_len);
    snprintf(name, sizeof(name), "%s payload ptr", label);
    check_int(name, (long)(uintptr_t)obs->payload_data,
              (long)(uintptr_t)want->payload_data);
    snprintf(name, sizeof(name), "%s dns txid valid", label);
    check_int(name, obs->dns_txid_valid, want->dns_txid_valid);
    snprintf(name, sizeof(name), "%s dns txid", label);
    check_int(name, obs->dns_txid, want->dns_txid);
}

static void test_loopback_plan_does_not_mutate_flag_before_execution(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;

    init_engine(&engine, &cfg, &dns_hijack);
    memset(&ctx, 0, sizeof(ctx));
    memset(&buf, 0, sizeof(buf));
    reset_counters();

    cfg.proxy.ip_addr = LOOPBACK_ADDR;
    cfg.proxy.port = 7890;
    buf.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
    ctx.ndis_buf = &buf;
    ctx.dst_ip = LOOPBACK_ADDR;
    ctx.dst_port = cfg.proxy.port;
    ctx.src_ip = 0x0200000AU;
    ctx.src_port = 12345;

    traffic_action_pass(&action, &ctx, &buf, "self-proxy direct");
    path_plan_bypass(&engine, packet_observe(&ctx), &action, "self-proxy direct");

    check_int("loopback flag preserved in plan",
              (long)buf.m_dwDeviceFlags, (long)PACKET_FLAG_ON_SEND);
}

static void test_loopback_pass_is_routed_by_executor(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;

    init_engine(&engine, &cfg, &dns_hijack);
    memset(&ctx, 0, sizeof(ctx));
    memset(&buf, 0, sizeof(buf));
    reset_counters();

    cfg.proxy.ip_addr = LOOPBACK_ADDR;
    cfg.proxy.port = 7890;
    buf.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
    ctx.ndis_buf = &buf;
    ctx.dst_ip = LOOPBACK_ADDR;
    ctx.dst_port = cfg.proxy.port;
    ctx.src_ip = 0x0200000AU;
    ctx.src_port = 12345;

    traffic_action_pass(&action, &ctx, &buf, "self-proxy direct");
    path_plan_bypass(&engine, packet_observe(&ctx), &action, "self-proxy direct");
    traffic_execute_action(&engine, &action);

    check_int("loopback sent to adapter", g_test_adapter_send_count, 0);
    check_int("loopback sent to mstcp", g_test_mstcp_send_count, 1);
    check_int("loopback not dropped", g_test_drop_count, 0);
}

static void test_direct_plan_keeps_packet_facts_stable_until_execution(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;

    init_engine(&engine, &cfg, &dns_hijack);
    memset(&ctx, 0, sizeof(ctx));
    memset(&buf, 0, sizeof(buf));
    reset_counters();

    cfg.proxy.ip_addr = htonl(0x7F000001U);
    cfg.proxy.port = 7890;
    buf.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
    ctx.ndis_buf = &buf;
    ctx.dst_ip = htonl(0x7F000001U);
    ctx.dst_port = cfg.proxy.port;
    ctx.src_ip = htonl(0x0A000002U);
    ctx.src_port = 12345;

    traffic_action_pass(&action, &ctx, &buf, "pre-plan");
    path_plan_bypass(&engine, packet_observe(&ctx), &action, "self-proxy direct");

    check_int("planner leaves packet flag alone",
              (long)buf.m_dwDeviceFlags, (long)PACKET_FLAG_ON_SEND);
    check_int("planner sets explicit send target",
              (long)action.send_target, (long)TRAFFIC_SEND_TO_MSTCP);
}

static void set_tcp_context(packet_ctx_t *ctx, INTERMEDIATE_BUFFER *buf,
                            uint32_t src_ip, uint16_t src_port,
                            uint32_t dst_ip, uint16_t dst_port,
                            uint8_t flags) {
    ether_header_ptr eth = (ether_header_ptr)buf->m_IBuffer;
    iphdr_ptr ip = (iphdr_ptr)(buf->m_IBuffer + ETHER_HDR_LEN);
    tcphdr_ptr tcp = (tcphdr_ptr)(buf->m_IBuffer + ETHER_HDR_LEN + 20);

    memset(ctx, 0, sizeof(*ctx));
    memset(buf, 0, sizeof(*buf));

    eth->h_proto = htons(ETH_P_IP);
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_p = WTP_IPPROTO_TCP;
    ip->ip_src = src_ip;
    ip->ip_dst = dst_ip;
    tcp->th_sport = htons(src_port);
    tcp->th_dport = htons(dst_port);
    tcp->th_off = 5;
    tcp->th_flags = flags;

    buf->m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
    buf->m_Length = ETHER_HDR_LEN + 20 + 20;
    ctx->ndis_buf = buf;
    ctx->packet = buf->m_IBuffer;
    ctx->packet_len = buf->m_Length;
    ctx->eth_hdr = eth;
    ctx->ip_hdr = ip;
    ctx->tcp_hdr = tcp;
    ctx->src_ip = src_ip;
    ctx->dst_ip = dst_ip;
    ctx->src_port = src_port;
    ctx->dst_port = dst_port;
    ctx->protocol = WTP_IPPROTO_TCP;
}

static void set_udp_context(packet_ctx_t *ctx, INTERMEDIATE_BUFFER *buf,
                            uint32_t src_ip, uint16_t src_port,
                            uint32_t dst_ip, uint16_t dst_port) {
    ether_header_ptr eth = (ether_header_ptr)buf->m_IBuffer;
    iphdr_ptr ip = (iphdr_ptr)(buf->m_IBuffer + ETHER_HDR_LEN);
    udphdr_ptr udp = (udphdr_ptr)(buf->m_IBuffer + ETHER_HDR_LEN + 20);

    memset(ctx, 0, sizeof(*ctx));
    memset(buf, 0, sizeof(*buf));

    eth->h_proto = htons(ETH_P_IP);
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_p = WTP_IPPROTO_UDP;
    ip->ip_src = src_ip;
    ip->ip_dst = dst_ip;
    udp->uh_sport = htons(src_port);
    udp->uh_dport = htons(dst_port);
    udp->uh_ulen = htons(8);

    buf->m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
    buf->m_Length = ETHER_HDR_LEN + 20 + 8;
    ctx->ndis_buf = buf;
    ctx->packet = buf->m_IBuffer;
    ctx->packet_len = buf->m_Length;
    ctx->eth_hdr = eth;
    ctx->ip_hdr = ip;
    ctx->udp_hdr = udp;
    ctx->src_ip = src_ip;
    ctx->dst_ip = dst_ip;
    ctx->src_port = src_port;
    ctx->dst_port = dst_port;
    ctx->protocol = WTP_IPPROTO_UDP;
}

static void set_udp_dns_context(packet_ctx_t *ctx, INTERMEDIATE_BUFFER *buf,
                                uint32_t src_ip, uint16_t src_port,
                                uint32_t dst_ip, uint16_t dst_port,
                                uint16_t txid) {
    set_udp_context(ctx, buf, src_ip, src_port, dst_ip, dst_port);
    uint8_t *payload = buf->m_IBuffer + ETHER_HDR_LEN + 20 + 8;
    payload[0] = (uint8_t)(txid >> 8);
    payload[1] = (uint8_t)(txid & 0xFF);
    buf->m_Length += 2;
    ctx->packet_len = buf->m_Length;
    ctx->payload_data = payload;
    ctx->payload_len = 2;
    ctx->payload_valid = 1;
    ctx->dns_txid = txid;
    ctx->dns_txid_valid = 1;
}

static void test_batch_executor_groups_mstcp_driver_sends(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    INTERMEDIATE_BUFFER bufs[2];
    traffic_action_t actions[2];

    init_engine(&engine, &cfg, &dns_hijack);
    memset(bufs, 0, sizeof(bufs));
    reset_counters();

    bufs[0].m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    bufs[1].m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    traffic_action_pass_raw(&actions[0], bufs[0].m_IBuffer, 0,
                            &bufs[0], "batch inbound 1");
    traffic_action_pass_raw(&actions[1], bufs[1].m_IBuffer, 0,
                            &bufs[1], "batch inbound 2");

    traffic_execute_actions(&engine, actions, 2);

    check_int("batch mstcp packet count", g_test_mstcp_send_count, 2);
    check_int("batch mstcp driver calls", g_test_mstcp_send_call_count, 1);
    check_int("batch mstcp adapter packets", g_test_adapter_send_count, 0);
    check_int("batch mstcp adapter driver calls", g_test_adapter_send_call_count, 0);
}

static void test_batch_executor_groups_adapter_driver_sends_after_rewrite(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctxs[2];
    INTERMEDIATE_BUFFER bufs[2];
    traffic_action_t actions[2];
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    set_udp_context(&ctxs[0], &bufs[0], client_ip, 11111, server_ip, 53);
    set_udp_context(&ctxs[1], &bufs[1], client_ip, 22222, server_ip, 443);

    traffic_action_rewrite_send(&actions[0], &ctxs[0], &bufs[0],
                                "batch rewrite adapter");
    traffic_action_rewrite_udp_dport(&actions[0], 5353);
    traffic_action_pass(&actions[1], &ctxs[1], &bufs[1], "batch pass adapter");

    traffic_execute_actions(&engine, actions, 2);

    check_int("batch adapter packet count", g_test_adapter_send_count, 2);
    check_int("batch adapter driver calls", g_test_adapter_send_call_count, 1);
    check_int("batch adapter mstcp packets", g_test_mstcp_send_count, 0);
    check_int("batch adapter mstcp driver calls", g_test_mstcp_send_call_count, 0);
    check_int("batch adapter rewrite applied",
              (long)ntohs(ctxs[0].udp_hdr->uh_dport), 5353);
}

static void test_batch_executor_preserves_mixed_action_outcomes(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctxs[3];
    INTERMEDIATE_BUFFER bufs[5];
    traffic_action_t actions[5];
    traffic_dns_forward_t fw;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);
    uint32_t dns_ip = htonl(0x01010101U);

    init_engine(&engine, &cfg, &dns_hijack);
    memset(bufs, 0, sizeof(bufs));
    memset(&fw, 0, sizeof(fw));
    reset_counters();

    engine.udp_fwd_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    engine.udp_relay_port = 9;

    bufs[0].m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    traffic_action_pass_raw(&actions[0], bufs[0].m_IBuffer, 0,
                            &bufs[0], "mixed inbound pass");

    set_udp_context(&ctxs[0], &bufs[1], client_ip, 11111, server_ip, 443);
    traffic_action_rewrite_send(&actions[1], &ctxs[0], &bufs[1],
                                "mixed adapter rewrite");
    traffic_action_rewrite_udp_dport(&actions[1], 8443);

    traffic_action_drop(&actions[2], NULL, &bufs[2], "mixed drop");

    set_udp_dns_context(&ctxs[1], &bufs[3], client_ip, 22222,
                        server_ip, 5300, 0xCAFE);
    traffic_action_forward_udp(&actions[3], &ctxs[1], &bufs[3],
                               "mixed udp forward");

    set_udp_dns_context(&ctxs[2], &bufs[4], client_ip, 33333,
                        dns_ip, 53, 0x1234);
    fw.src_port = 33333;
    fw.original_dns_ip = dns_ip;
    fw.original_dns_port = 53;
    fw.client_ip = client_ip;
    fw.adapter_handle = (HANDLE)0x77;
    traffic_action_forward_dns(&actions[4], &ctxs[2], &bufs[4],
                               &fw, "mixed dns forward");

    traffic_execute_actions(&engine, actions, 5);

    check_int("mixed batch mstcp packets", g_test_mstcp_send_count, 1);
    check_int("mixed batch mstcp driver calls", g_test_mstcp_send_call_count, 1);
    check_int("mixed batch adapter packets", g_test_adapter_send_count, 1);
    check_int("mixed batch adapter driver calls", g_test_adapter_send_call_count, 1);
    check_int("mixed batch drop count", g_test_drop_count, 1);
    check_int("mixed batch udp forwarded", g_test_udp_forwarded_count, 1);
    check_int("mixed batch dns forwarded", g_test_dns_forwarded_count, 1);
    check_int("mixed batch rewrite applied",
              (long)ntohs(ctxs[0].udp_hdr->uh_dport), 8443);

    if (engine.udp_fwd_sock != INVALID_SOCKET) {
        closesocket(engine.udp_fwd_sock);
    }
}

static void test_pass_planning_keeps_observation_snapshot(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    const packet_observation_t *obs;
    observation_snapshot_t before;

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    set_tcp_context(&ctx, &buf, htonl(0x0A000002U), 12345,
                    htonl(0x08080808U), 443, TH_SYN);
    obs = packet_observe(&ctx);
    before = snapshot_observation(obs);

    path_plan_bypass(&engine, obs, &action, "direct observation");

    check_observation_snapshot("pass plan observation", obs, &before);
    check_int("pass plan action", (long)action.type, (long)TRAFFIC_ACTION_PASS);
}

static void test_rewrite_execution_updates_frame_not_observation(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    const packet_observation_t *obs;
    observation_snapshot_t before;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_PROXY;
    engine.tcp_relay_port = 34010;

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_SYN);
    obs = packet_observe(&ctx);
    before = snapshot_observation(obs);

    path_plan_policy(&engine, obs, &action);
    check_observation_snapshot("rewrite plan observation", obs, &before);

    traffic_execute_action(&engine, &action);

    check_int("rewrite frame src ip changed",
              (long)ctx.ip_hdr->ip_src, (long)server_ip);
    check_int("rewrite frame dst ip changed",
              (long)ctx.ip_hdr->ip_dst, (long)client_ip);
    check_int("rewrite observation src ip stable",
              (long)obs->src_ip, (long)before.src_ip);
    check_int("rewrite observation dst ip stable",
              (long)obs->dst_ip, (long)before.dst_ip);
    check_observation_snapshot("rewrite execute observation", obs, &before);
}

static void test_dns_planning_keeps_txid_payload_observation(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    const packet_observation_t *obs;
    observation_snapshot_t before;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t original_dns_ip = htonl(0x01010101U);
    uint32_t redirect_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    dns_hijack.enabled = 1;
    dns_hijack.redirect_ip = redirect_ip;
    dns_hijack.redirect_port = 5353;
    g_test_dns_rewrite_request_hit = 1;
    g_test_dns_rewrite_request_ip = redirect_ip;
    g_test_dns_rewrite_request_port = 5353;

    set_udp_dns_context(&ctx, &buf, client_ip, 12345,
                        original_dns_ip, 53, 0x1234);
    obs = packet_observe(&ctx);
    before = snapshot_observation(obs);

    dns_plan_udp_query(&engine, obs, &action);

    check_int("dns observation txid valid", obs->dns_txid_valid, 1);
    check_int("dns observation txid", obs->dns_txid, 0x1234);
    check_int("dns observation payload len", (long)obs->payload_len, 2);
    check_observation_snapshot("dns plan observation", obs, &before);
}

static void test_return_planning_keeps_observation_snapshot(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    const packet_observation_t *obs;
    observation_snapshot_t before;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    engine.tcp_relay_port = 34010;
    g_test_conntrack_tcp_proxy_return_hit = 1;
    g_test_conntrack_entry.key_src_ip = server_ip;
    g_test_conntrack_entry.src_port = 40000;
    g_test_conntrack_entry.key_dst_ip = client_ip;
    g_test_conntrack_entry.key_dst_port = 34010;
    g_test_conntrack_entry.src_ip = client_ip;
    g_test_conntrack_entry.client_port = 12345;
    g_test_conntrack_entry.orig_dst_ip = server_ip;
    g_test_conntrack_entry.orig_dst_port = 443;
    g_test_conntrack_entry.relay_src_port = 40000;

    set_tcp_context(&ctx, &buf, client_ip, 34010, server_ip, 40000, TH_ACK);
    obs = packet_observe(&ctx);
    before = snapshot_observation(obs);

    path_plan_return(&engine, obs, 1, &action);
    check_observation_snapshot("return plan observation", obs, &before);

    traffic_execute_action(&engine, &action);
    check_int("return frame src ip changed",
              (long)ctx.ip_hdr->ip_src, (long)server_ip);
    check_int("return frame dst ip changed",
              (long)ctx.ip_hdr->ip_dst, (long)client_ip);
    check_observation_snapshot("return execute observation", obs, &before);
}

static void test_direct_tcp_uses_role_contract_and_tracks_non_syn(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_DIRECT;
    engine.tcp_relay_port = 34010;
    engine.udp_relay_port = 34011;

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_SYN);
    traffic_plan_packet(&engine, packet_observe(&ctx), &action);

    check_int("direct tcp role track count",
              g_test_conntrack_direct_tcp_track_count, 1);
    check_int("direct tcp raw full-key add hidden",
              g_test_conntrack_raw_full_key_add_count, 0);
    check_int("direct tcp syn passes",
              (long)action.type, (long)TRAFFIC_ACTION_PASS);

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_ACK);
    traffic_plan_packet(&engine, packet_observe(&ctx), &action);

    check_int("direct tcp tracked non-syn passes",
              (long)action.type, (long)TRAFFIC_ACTION_PASS);
    check_int("direct tcp tracked non-syn uses fused role op",
              g_test_conntrack_role_tcp_outbound_count, 1);
}

static void test_tcp_proxy_uses_role_contract_creation(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_PROXY;
    engine.tcp_relay_port = 34010;

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_SYN);
    path_plan_policy(&engine, packet_observe(&ctx), &action);

    check_int("tcp proxy role track count",
              g_test_conntrack_tcp_proxy_track_count, 1);
    check_int("tcp proxy raw full-key add hidden",
              g_test_conntrack_raw_full_key_add_count, 0);
    check_int("tcp proxy role action",
              (long)action.type, (long)TRAFFIC_ACTION_REWRITE_SEND);
}

static void test_udp_proxy_uses_role_contract_creation(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_PROXY;
    engine.udp_relay_port = 34011;

    set_udp_dns_context(&ctx, &buf, client_ip, 12345,
                        server_ip, 5300, 0xCAFE);
    path_plan_policy(&engine, packet_observe(&ctx), &action);

    check_int("udp proxy role track count",
              g_test_conntrack_udp_proxy_track_count, 1);
    check_int("udp proxy raw full-key add hidden",
              g_test_conntrack_raw_full_key_add_count, 0);
    check_int("udp proxy role action",
              (long)action.type, (long)TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY);
}

static void test_tcp_dns_uses_role_contract_creation(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t original_dns_ip = htonl(0x01010101U);
    uint32_t redirect_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    dns_hijack.enabled = 1;
    dns_hijack.redirect_ip = redirect_ip;
    dns_hijack.redirect_port = 5353;

    set_tcp_context(&ctx, &buf, client_ip, 12345,
                    original_dns_ip, 53, TH_SYN);
    dns_plan_tcp_query(&engine, packet_observe(&ctx), &action);

    check_int("tcp dns role track count",
              g_test_conntrack_tcp_dns_track_count, 1);
    check_int("tcp dns raw full-key add hidden",
              g_test_conntrack_raw_full_key_add_count, 0);
    check_int("tcp dns role action",
              (long)action.type, (long)TRAFFIC_ACTION_REWRITE_SEND);
}

static void test_relay_consumes_tcp_and_udp_role_contracts(void) {
    conntrack_entry_t entry;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    reset_counters();

    g_test_conntrack_tcp_proxy_return_hit = 1;
    g_test_conntrack_entry.key_src_ip = server_ip;
    g_test_conntrack_entry.src_port = 40000;
    g_test_conntrack_entry.key_dst_ip = client_ip;
    g_test_conntrack_entry.key_dst_port = 34010;
    g_test_conntrack_entry.src_ip = client_ip;
    g_test_conntrack_entry.client_port = 12345;
    g_test_conntrack_entry.orig_dst_ip = server_ip;
    g_test_conntrack_entry.orig_dst_port = 443;
    g_test_conntrack_entry.connect_dst_ip = server_ip;
    g_test_conntrack_entry.connect_dst_port = 443;
    g_test_conntrack_entry.relay_src_port = 40000;

    check_int("tcp relay setup full-entry lookup",
              conntrack_get_tcp_proxy_return(NULL, server_ip, 40000,
                                             client_ip, 34010, &entry),
              ERR_OK);
    check_int("tcp relay role original port", entry.orig_dst_port, 443);
    conntrack_role_refresh_tcp_pair(NULL, &entry);
    check_int("tcp relay periodic pair refresh is conntrack-owned",
              g_test_conntrack_role_refresh_tcp_pair_count, 1);

    reset_counters();

    g_test_conntrack_udp_proxy_outbound_hit = 1;
    g_test_conntrack_entry.key_src_ip = client_ip;
    g_test_conntrack_entry.src_port = 12345;
    g_test_conntrack_entry.key_dst_ip = server_ip;
    g_test_conntrack_entry.key_dst_port = 53;
    g_test_conntrack_entry.src_ip = client_ip;
    g_test_conntrack_entry.client_port = 12345;
    g_test_conntrack_entry.orig_dst_ip = server_ip;
    g_test_conntrack_entry.orig_dst_port = 53;

    check_int("udp relay role lookup",
              conntrack_get_udp_proxy_outbound(NULL, client_ip, 12345,
                                               server_ip, 53, &entry),
              ERR_OK);
    check_int("udp relay role original port", entry.orig_dst_port, 53);
    /* Liveness is owned by packet-path role ops; relays issue no touches. */
}

static void test_tcp_proxy_plan_does_not_mutate_packet_until_execution(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_PROXY;
    engine.tcp_relay_port = 34010;

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_SYN);

    path_plan_policy(&engine, packet_observe(&ctx), &action);

    check_int("tcp proxy plan action",
              (long)action.type, (long)TRAFFIC_ACTION_REWRITE_SEND);
    check_int("tcp proxy send target",
              (long)action.send_target, (long)TRAFFIC_SEND_TO_MSTCP);
    check_int("tcp proxy src ip preserved before execute",
              (long)ctx.ip_hdr->ip_src, (long)client_ip);
    check_int("tcp proxy dst ip preserved before execute",
              (long)ctx.ip_hdr->ip_dst, (long)server_ip);
    check_int("tcp proxy src port preserved before execute",
              (long)ntohs(ctx.tcp_hdr->th_sport), 12345);
    check_int("tcp proxy dst port preserved before execute",
              (long)ntohs(ctx.tcp_hdr->th_dport), 443);
    check_int("tcp proxy flag preserved before execute",
              (long)buf.m_dwDeviceFlags, (long)PACKET_FLAG_ON_SEND);
}

static void test_tcp_proxy_rewrite_applies_during_execution(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_PROXY;
    engine.tcp_relay_port = 34010;

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_SYN);

    path_plan_policy(&engine, packet_observe(&ctx), &action);
    traffic_execute_action(&engine, &action);

    check_int("tcp proxy sent to adapter", g_test_adapter_send_count, 0);
    check_int("tcp proxy sent to mstcp", g_test_mstcp_send_count, 1);
    check_int("tcp proxy src ip rewritten on execute",
              (long)ctx.ip_hdr->ip_src, (long)server_ip);
    check_int("tcp proxy dst ip rewritten on execute",
              (long)ctx.ip_hdr->ip_dst, (long)client_ip);
    check_int("tcp proxy src port rewritten on execute",
              (long)ntohs(ctx.tcp_hdr->th_sport), 40000);
    check_int("tcp proxy dst port rewritten on execute",
              (long)ntohs(ctx.tcp_hdr->th_dport), 34010);
    check_int("tcp proxy flag still observed fact",
              (long)buf.m_dwDeviceFlags, (long)PACKET_FLAG_ON_SEND);
}

static void test_tracked_tcp_proxy_non_syn_waits_for_executor_rewrite(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_PROXY;
    engine.tcp_relay_port = 34010;
    g_test_conntrack_tcp_proxy_outbound_hit = 1;
    g_test_conntrack_entry.key_src_ip = client_ip;
    g_test_conntrack_entry.src_port = 12345;
    g_test_conntrack_entry.key_dst_ip = server_ip;
    g_test_conntrack_entry.key_dst_port = 443;
    g_test_conntrack_entry.src_ip = client_ip;
    g_test_conntrack_entry.client_port = 12345;
    g_test_conntrack_entry.orig_dst_ip = server_ip;
    g_test_conntrack_entry.orig_dst_port = 443;
    g_test_conntrack_entry.relay_src_port = 40000;

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_ACK);

    path_plan_policy(&engine, packet_observe(&ctx), &action);

    check_int("tracked non-syn plan rewrite action",
              (long)action.type, (long)TRAFFIC_ACTION_REWRITE_SEND);
    check_int("tracked non-syn plan send target",
              (long)action.send_target, (long)TRAFFIC_SEND_TO_MSTCP);
    check_int("tracked non-syn src ip preserved before execute",
              (long)ctx.ip_hdr->ip_src, (long)client_ip);
    check_int("tracked non-syn dst ip preserved before execute",
              (long)ctx.ip_hdr->ip_dst, (long)server_ip);
    check_int("tracked non-syn src port preserved before execute",
              (long)ntohs(ctx.tcp_hdr->th_sport), 12345);
    check_int("tracked non-syn dst port preserved before execute",
              (long)ntohs(ctx.tcp_hdr->th_dport), 443);
    check_int("tracked non-syn flag preserved before execute",
              (long)buf.m_dwDeviceFlags, (long)PACKET_FLAG_ON_SEND);

    traffic_execute_action(&engine, &action);

    check_int("tracked non-syn sent to adapter", g_test_adapter_send_count, 0);
    check_int("tracked non-syn sent to mstcp", g_test_mstcp_send_count, 1);
    check_int("tracked non-syn src ip rewritten on execute",
              (long)ctx.ip_hdr->ip_src, (long)server_ip);
    check_int("tracked non-syn dst ip rewritten on execute",
              (long)ctx.ip_hdr->ip_dst, (long)client_ip);
    check_int("tracked non-syn src port rewritten on execute",
              (long)ntohs(ctx.tcp_hdr->th_sport), 40000);
    check_int("tracked non-syn dst port rewritten on execute",
              (long)ntohs(ctx.tcp_hdr->th_dport), 34010);
}

static void test_tcp_proxy_return_waits_for_executor_rewrite(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    engine.tcp_relay_port = 34010;
    g_test_conntrack_tcp_proxy_return_hit = 1;
    g_test_conntrack_entry.key_src_ip = server_ip;
    g_test_conntrack_entry.src_port = 40000;
    g_test_conntrack_entry.key_dst_ip = client_ip;
    g_test_conntrack_entry.key_dst_port = 34010;
    g_test_conntrack_entry.src_ip = client_ip;
    g_test_conntrack_entry.client_port = 12345;
    g_test_conntrack_entry.orig_dst_ip = server_ip;
    g_test_conntrack_entry.orig_dst_port = 443;
    g_test_conntrack_entry.relay_src_port = 40000;

    set_tcp_context(&ctx, &buf, client_ip, 34010, server_ip, 40000, TH_ACK);

    path_plan_return(&engine, packet_observe(&ctx), 1, &action);

    check_int("tcp return plan rewrite action",
              (long)action.type, (long)TRAFFIC_ACTION_REWRITE_SEND);
    check_int("tcp return plan send target",
              (long)action.send_target, (long)TRAFFIC_SEND_TO_MSTCP);
    check_int("tcp return src ip preserved before execute",
              (long)ctx.ip_hdr->ip_src, (long)client_ip);
    check_int("tcp return dst ip preserved before execute",
              (long)ctx.ip_hdr->ip_dst, (long)server_ip);
    check_int("tcp return src port preserved before execute",
              (long)ntohs(ctx.tcp_hdr->th_sport), 34010);
    check_int("tcp return dst port preserved before execute",
              (long)ntohs(ctx.tcp_hdr->th_dport), 40000);
    check_int("tcp return flag preserved before execute",
              (long)buf.m_dwDeviceFlags, (long)PACKET_FLAG_ON_SEND);

    traffic_execute_action(&engine, &action);

    check_int("tcp return sent to adapter", g_test_adapter_send_count, 0);
    check_int("tcp return sent to mstcp", g_test_mstcp_send_count, 1);
    check_int("tcp return src ip rewritten on execute",
              (long)ctx.ip_hdr->ip_src, (long)server_ip);
    check_int("tcp return dst ip rewritten on execute",
              (long)ctx.ip_hdr->ip_dst, (long)client_ip);
    check_int("tcp return src port rewritten on execute",
              (long)ntohs(ctx.tcp_hdr->th_sport), 443);
    check_int("tcp return dst port rewritten on execute",
              (long)ntohs(ctx.tcp_hdr->th_dport), 12345);
    check_int("tcp return role op fused lookup and refresh",
              g_test_conntrack_role_tcp_return_count, 1);
}

static void test_tcp_proxy_return_missing_state_drops_closed(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    engine.tcp_relay_port = 34010;

    set_tcp_context(&ctx, &buf, client_ip, 34010, server_ip, 40000, TH_ACK);

    path_plan_return(&engine, packet_observe(&ctx), 1, &action);

    check_int("tcp return missing state plan drop",
              (long)action.type, (long)TRAFFIC_ACTION_DROP);
    check_int("tcp return missing state src ip stable",
              (long)ctx.ip_hdr->ip_src, (long)client_ip);
    check_int("tcp return missing state dst ip stable",
              (long)ctx.ip_hdr->ip_dst, (long)server_ip);

    traffic_execute_action(&engine, &action);

    check_int("tcp return missing state not adapter",
              g_test_adapter_send_count, 0);
    check_int("tcp return missing state not mstcp",
              g_test_mstcp_send_count, 0);
    check_int("tcp return missing state dropped",
              g_test_drop_count, 1);
}

static void test_udp_proxy_return_waits_for_executor_rewrite(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    engine.udp_relay_port = 34011;
    g_test_conntrack_udp_proxy_return_hit = 1;
    g_test_conntrack_entry.key_src_ip = server_ip;
    g_test_conntrack_entry.src_port = 12345;
    g_test_conntrack_entry.src_ip = client_ip;
    g_test_conntrack_entry.client_port = 12345;
    g_test_conntrack_entry.orig_dst_ip = server_ip;
    g_test_conntrack_entry.orig_dst_port = 53;

    set_udp_context(&ctx, &buf, client_ip, 34011, server_ip, 12345);

    path_plan_return(&engine, packet_observe(&ctx), 0, &action);

    check_int("udp return plan rewrite action",
              (long)action.type, (long)TRAFFIC_ACTION_REWRITE_SEND);
    check_int("udp return plan send target",
              (long)action.send_target, (long)TRAFFIC_SEND_TO_MSTCP);
    check_int("udp return src ip preserved before execute",
              (long)ctx.ip_hdr->ip_src, (long)client_ip);
    check_int("udp return dst ip preserved before execute",
              (long)ctx.ip_hdr->ip_dst, (long)server_ip);
    check_int("udp return src port preserved before execute",
              (long)ntohs(ctx.udp_hdr->uh_sport), 34011);
    check_int("udp return dst port preserved before execute",
              (long)ntohs(ctx.udp_hdr->uh_dport), 12345);

    traffic_execute_action(&engine, &action);

    check_int("udp return sent to adapter", g_test_adapter_send_count, 0);
    check_int("udp return sent to mstcp", g_test_mstcp_send_count, 1);
    check_int("udp return src ip rewritten on execute",
              (long)ctx.ip_hdr->ip_src, (long)server_ip);
    check_int("udp return dst ip rewritten on execute",
              (long)ctx.ip_hdr->ip_dst, (long)client_ip);
    check_int("udp return src port rewritten on execute",
              (long)ntohs(ctx.udp_hdr->uh_sport), 53);
    check_int("udp return dst port preserved on execute",
              (long)ntohs(ctx.udp_hdr->uh_dport), 12345);
    check_int("udp return role op fused lookup and refresh",
              g_test_conntrack_role_udp_return_count, 1);
}

static void test_udp_proxy_return_missing_state_drops_closed(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    engine.udp_relay_port = 34011;

    set_udp_context(&ctx, &buf, client_ip, 34011, server_ip, 12345);

    path_plan_return(&engine, packet_observe(&ctx), 0, &action);

    check_int("udp return missing state plan drop",
              (long)action.type, (long)TRAFFIC_ACTION_DROP);
    check_int("udp return missing state src ip stable",
              (long)ctx.ip_hdr->ip_src, (long)client_ip);
    check_int("udp return missing state dst ip stable",
              (long)ctx.ip_hdr->ip_dst, (long)server_ip);

    traffic_execute_action(&engine, &action);

    check_int("udp return missing state not adapter",
              g_test_adapter_send_count, 0);
    check_int("udp return missing state not mstcp",
              g_test_mstcp_send_count, 0);
    check_int("udp return missing state dropped",
              g_test_drop_count, 1);
}

static void test_udp_dns_query_waits_for_executor_rewrite(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t original_dns_ip = htonl(0x01010101U);
    uint32_t redirect_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    dns_hijack.enabled = 1;
    dns_hijack.redirect_ip = redirect_ip;
    dns_hijack.redirect_port = 5353;
    g_test_dns_rewrite_request_hit = 1;
    g_test_dns_rewrite_request_ip = redirect_ip;
    g_test_dns_rewrite_request_port = 5353;

    set_udp_dns_context(&ctx, &buf, client_ip, 12345,
                        original_dns_ip, 53, 0x1234);

    dns_plan_udp_query(&engine, packet_observe(&ctx), &action);

    check_int("udp dns query plan rewrite action",
              (long)action.type, (long)TRAFFIC_ACTION_REWRITE_SEND);
    check_int("udp dns query dst ip preserved before execute",
              (long)ctx.ip_hdr->ip_dst, (long)original_dns_ip);
    check_int("udp dns query dst port preserved before execute",
              (long)ntohs(ctx.udp_hdr->uh_dport), 53);

    traffic_execute_action(&engine, &action);

    check_int("udp dns query sent to adapter", g_test_adapter_send_count, 1);
    check_int("udp dns query sent to mstcp", g_test_mstcp_send_count, 0);
    check_int("udp dns query dst ip rewritten on execute",
              (long)ctx.ip_hdr->ip_dst, (long)redirect_ip);
    check_int("udp dns query dst port rewritten on execute",
              (long)ntohs(ctx.udp_hdr->uh_dport), 5353);
}

static void test_udp_dns_response_waits_for_executor_rewrite(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t redirect_ip = htonl(0x08080808U);
    uint32_t original_dns_ip = htonl(0x01010101U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    dns_hijack.enabled = 1;
    dns_hijack.redirect_ip = redirect_ip;
    dns_hijack.redirect_port = 5353;
    g_test_dns_rewrite_response_hit = 1;
    g_test_dns_rewrite_response_ip = original_dns_ip;
    g_test_dns_rewrite_response_port = 53;

    set_udp_dns_context(&ctx, &buf, redirect_ip, 5353,
                        client_ip, 12345, 0x1234);
    buf.m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;

    dns_plan_inbound_or_response(&engine, packet_observe(&ctx), 1, &action);

    check_int("udp dns response plan rewrite action",
              (long)action.type, (long)TRAFFIC_ACTION_REWRITE_SEND);
    check_int("udp dns response src ip preserved before execute",
              (long)ctx.ip_hdr->ip_src, (long)redirect_ip);
    check_int("udp dns response src port preserved before execute",
              (long)ntohs(ctx.udp_hdr->uh_sport), 5353);
    check_int("udp dns response flag preserved before execute",
              (long)buf.m_dwDeviceFlags, (long)PACKET_FLAG_ON_RECEIVE);

    traffic_execute_action(&engine, &action);

    check_int("udp dns response sent to mstcp", g_test_mstcp_send_count, 1);
    check_int("udp dns response src ip rewritten on execute",
              (long)ctx.ip_hdr->ip_src, (long)original_dns_ip);
    check_int("udp dns response src port rewritten on execute",
              (long)ntohs(ctx.udp_hdr->uh_sport), 53);
}

static void test_loopback_udp_dns_query_forwards_without_packet_mutation(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t original_dns_ip = htonl(0x01010101U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    dns_hijack.enabled = 1;
    dns_hijack.redirect_ip = LOOPBACK_ADDR;
    dns_hijack.redirect_port = 5353;
    dns_hijack.use_socket_fwd = 1;

    set_udp_dns_context(&ctx, &buf, client_ip, 12345,
                        original_dns_ip, 53, 0x1234);
    buf.m_hAdapter = (HANDLE)0x55;

    dns_plan_udp_query(&engine, packet_observe(&ctx), &action);

    check_int("loopback dns plan forward action",
              (long)action.type, (long)TRAFFIC_ACTION_FORWARD_DNS_TO_RESOLVER);
    check_int("loopback dns original src port recorded",
              (long)action.dns_forward.src_port, 12345);
    check_int("loopback dns original ip recorded",
              (long)action.dns_forward.original_dns_ip, (long)original_dns_ip);
    check_int("loopback dns original port recorded",
              (long)action.dns_forward.original_dns_port, 53);
    check_int("loopback dns client ip recorded",
              (long)action.dns_forward.client_ip, (long)client_ip);
    check_int("loopback dns dst ip preserved before execute",
              (long)ctx.ip_hdr->ip_dst, (long)original_dns_ip);
    check_int("loopback dns dst port preserved before execute",
              (long)ntohs(ctx.udp_hdr->uh_dport), 53);
}

static void test_loopback_dns_forward_failure_drops_closed(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t original_dns_ip = htonl(0x01010101U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    dns_hijack.enabled = 1;
    dns_hijack.redirect_ip = LOOPBACK_ADDR;
    dns_hijack.redirect_port = 5353;
    dns_hijack.use_socket_fwd = 1;
    g_test_dns_forward_error = ERR_NETWORK;

    set_udp_dns_context(&ctx, &buf, client_ip, 12345,
                        original_dns_ip, 53, 0x1234);

    dns_plan_udp_query(&engine, packet_observe(&ctx), &action);
    traffic_execute_action(&engine, &action);

    check_int("loopback dns forward failure not adapter",
              g_test_adapter_send_count, 0);
    check_int("loopback dns forward failure not mstcp",
              g_test_mstcp_send_count, 0);
    check_int("loopback dns forward failure dropped",
              g_test_drop_count, 1);
}

static void test_loopback_dns_response_injection_uses_executor_send_path(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    traffic_action_t action;
    uint8_t dns_payload[4] = {0xAB, 0xCD, 0x81, 0x80};
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t original_dns_ip = htonl(0x01010101U);
    iphdr_ptr ip;
    udphdr_ptr udp;
    uint8_t *restored_dns;

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    engine.adapter_count = 1;
    engine.adapter_handles[0] = (HANDLE)0x55;
    engine.adapter_mac[0][0] = 0x02;
    engine.adapter_mac[0][5] = 0x55;

    traffic_action_inject_dns_response(&action, dns_payload, sizeof(dns_payload),
                                       0x1234, original_dns_ip, 53,
                                       client_ip, 12345,
                                       (HANDLE)0x55,
                                       "dns fwd response");
    traffic_execute_action(&engine, &action);

    check_int("dns response injection mstcp packets", g_test_mstcp_send_count, 1);
    check_int("dns response injection mstcp driver calls",
              g_test_mstcp_send_call_count, 1);
    check_int("dns response injection adapter packets", g_test_adapter_send_count, 0);
    check_int("dns response injection not dropped", g_test_drop_count, 0);
    check_int("dns response injection captured packet",
              g_test_last_mstcp_packet_valid, 1);
    check_int("dns response injection adapter",
              (long)(uintptr_t)g_test_last_mstcp_packet.m_hAdapter,
              (long)(uintptr_t)(HANDLE)0x55);
    check_int("dns response injection direction",
              (long)g_test_last_mstcp_packet.m_dwDeviceFlags,
              (long)PACKET_FLAG_ON_RECEIVE);

    ip = (iphdr_ptr)(g_test_last_mstcp_packet.m_IBuffer + ETHER_HDR_LEN);
    udp = (udphdr_ptr)(g_test_last_mstcp_packet.m_IBuffer + ETHER_HDR_LEN + 20);
    restored_dns = g_test_last_mstcp_packet.m_IBuffer + ETHER_HDR_LEN + 20 + 8;

    check_int("dns response injection src ip",
              (long)ip->ip_src, (long)original_dns_ip);
    check_int("dns response injection dst ip",
              (long)ip->ip_dst, (long)client_ip);
    check_int("dns response injection src port",
              (long)ntohs(udp->uh_sport), 53);
    check_int("dns response injection dst port",
              (long)ntohs(udp->uh_dport), 12345);
    check_int("dns response injection restored txid hi", restored_dns[0], 0x12);
    check_int("dns response injection restored txid lo", restored_dns[1], 0x34);
}

static void test_loopback_dns_malformed_response_injection_drops_closed(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    traffic_action_t action;
    uint8_t malformed_payload[1] = {0x12};

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    traffic_action_inject_dns_response(&action, malformed_payload,
                                       sizeof(malformed_payload),
                                       0x1234, htonl(0x01010101U), 53,
                                       htonl(0x0A000002U), 12345,
                                       (HANDLE)0x55,
                                       "dns malformed response");
    traffic_execute_action(&engine, &action);

    check_int("dns malformed response not mstcp", g_test_mstcp_send_count, 0);
    check_int("dns malformed response not adapter", g_test_adapter_send_count, 0);
    check_int("dns malformed response dropped", g_test_drop_count, 1);
}

static void test_loopback_dns_response_send_failure_fails_closed(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    traffic_action_t action;
    uint8_t dns_payload[4] = {0xAB, 0xCD, 0x81, 0x80};

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    g_test_mstcp_send_error = 1;
    traffic_action_inject_dns_response(&action, dns_payload, sizeof(dns_payload),
                                       0x1234, htonl(0x01010101U), 53,
                                       htonl(0x0A000002U), 12345,
                                       (HANDLE)0x55,
                                       "dns send failure");
    traffic_execute_action(&engine, &action);

    check_int("dns send failure no mstcp packet count", g_test_mstcp_send_count, 0);
    check_int("dns send failure no adapter", g_test_adapter_send_count, 0);
    check_int("dns send failure counted", g_test_send_failure_count, 1);
}

static void test_tcp_dns_query_waits_for_executor_rewrite(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t original_dns_ip = htonl(0x01010101U);
    uint32_t redirect_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    dns_hijack.enabled = 1;
    dns_hijack.redirect_ip = redirect_ip;
    dns_hijack.redirect_port = 5353;

    set_tcp_context(&ctx, &buf, client_ip, 12345,
                    original_dns_ip, 53, TH_SYN);

    dns_plan_tcp_query(&engine, packet_observe(&ctx), &action);

    check_int("tcp dns query plan rewrite action",
              (long)action.type, (long)TRAFFIC_ACTION_REWRITE_SEND);
    check_int("tcp dns query dst ip preserved before execute",
              (long)ctx.ip_hdr->ip_dst, (long)original_dns_ip);
    check_int("tcp dns query dst port preserved before execute",
              (long)ntohs(ctx.tcp_hdr->th_dport), 53);

    traffic_execute_action(&engine, &action);

    check_int("tcp dns query sent to adapter", g_test_adapter_send_count, 1);
    check_int("tcp dns query dst ip rewritten on execute",
              (long)ctx.ip_hdr->ip_dst, (long)redirect_ip);
    check_int("tcp dns query dst port rewritten on execute",
              (long)ntohs(ctx.tcp_hdr->th_dport), 5353);
}

static void test_loopback_tcp_dns_query_routes_to_mstcp_on_execute(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t original_dns_ip = htonl(0x01010101U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    dns_hijack.enabled = 1;
    dns_hijack.redirect_ip = LOOPBACK_ADDR;
    dns_hijack.redirect_port = 5353;

    set_tcp_context(&ctx, &buf, client_ip, 12345,
                    original_dns_ip, 53, TH_SYN);

    dns_plan_tcp_query(&engine, packet_observe(&ctx), &action);

    check_int("loopback tcp dns plan rewrite action",
              (long)action.type, (long)TRAFFIC_ACTION_REWRITE_SEND);
    check_int("loopback tcp dns send target",
              (long)action.send_target, (long)TRAFFIC_SEND_TO_MSTCP);
    check_int("loopback tcp dns flag preserved before execute",
              (long)buf.m_dwDeviceFlags, (long)PACKET_FLAG_ON_SEND);

    traffic_execute_action(&engine, &action);

    check_int("loopback tcp dns sent to adapter", g_test_adapter_send_count, 0);
    check_int("loopback tcp dns sent to mstcp", g_test_mstcp_send_count, 1);
    check_int("loopback tcp dns src ip rewritten on execute",
              (long)ctx.ip_hdr->ip_src, (long)original_dns_ip);
    check_int("loopback tcp dns dst ip rewritten on execute",
              (long)ctx.ip_hdr->ip_dst, (long)LOOPBACK_ADDR);
    check_int("loopback tcp dns dst port rewritten on execute",
              (long)ntohs(ctx.tcp_hdr->th_dport), 5353);
}

static void test_public_plan_non_proxyable_direct_uses_executor_owner(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t broadcast_ip = 0xFFFFFFFFU;

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.bypass.broadcast = 1;
    cfg.policy.default_decision = RULE_DECISION_PROXY;
    engine.tcp_relay_port = 34010;
    engine.udp_relay_port = 34011;

    set_tcp_context(&ctx, &buf, client_ip, 12345, broadcast_ip, 443, TH_SYN);

    traffic_plan_packet(&engine, packet_observe(&ctx), &action);

    check_int("non-proxyable plan pass",
              (long)action.type, (long)TRAFFIC_ACTION_PASS);
    check_int("non-proxyable plan leaves flag",
              (long)buf.m_dwDeviceFlags, (long)PACKET_FLAG_ON_SEND);

    traffic_execute_action(&engine, &action);

    check_int("non-proxyable sent to adapter", g_test_adapter_send_count, 1);
    check_int("non-proxyable sent to mstcp", g_test_mstcp_send_count, 0);
    check_int("non-proxyable not dropped", g_test_drop_count, 0);
}

static void test_public_plan_untracked_proxy_non_syn_drops_closed(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_PROXY;
    engine.tcp_relay_port = 34010;
    engine.udp_relay_port = 34011;

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_ACK);

    traffic_plan_packet(&engine, packet_observe(&ctx), &action);

    check_int("untracked proxy non-syn plan drop",
              (long)action.type, (long)TRAFFIC_ACTION_DROP);
    check_int("untracked proxy non-syn plan leaves src port",
              (long)ntohs(ctx.tcp_hdr->th_sport), 12345);
    check_int("untracked proxy non-syn plan leaves flag",
              (long)buf.m_dwDeviceFlags, (long)PACKET_FLAG_ON_SEND);

    traffic_execute_action(&engine, &action);

    check_int("untracked proxy non-syn not sent adapter",
              g_test_adapter_send_count, 0);
    check_int("untracked proxy non-syn not sent mstcp",
              g_test_mstcp_send_count, 0);
    check_int("untracked proxy non-syn dropped", g_test_drop_count, 1);
}

static void test_startup_quarantine_discards_preexisting_external_direct_tcp(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_DIRECT;
    engine.tcp_relay_port = 34010;
    engine.udp_relay_port = 34011;

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_ACK);

    traffic_plan_packet(&engine, packet_observe(&ctx), &action);

    check_int("startup quarantine preexisting direct tcp drops",
              (long)action.type, (long)TRAFFIC_ACTION_DROP);
    check_int("startup quarantine packet flag stable",
              (long)buf.m_dwDeviceFlags, (long)PACKET_FLAG_ON_SEND);

    traffic_execute_action(&engine, &action);

    check_int("startup quarantine not sent adapter",
              g_test_adapter_send_count, 0);
    check_int("startup quarantine not sent mstcp",
              g_test_mstcp_send_count, 0);
    check_int("startup quarantine dropped",
              g_test_drop_count, 1);
}

static void test_startup_quarantine_allows_new_direct_tcp_syn(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_DIRECT;
    engine.tcp_relay_port = 34010;
    engine.udp_relay_port = 34011;

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_SYN);

    traffic_plan_packet(&engine, packet_observe(&ctx), &action);

    check_int("startup quarantine new direct syn passes",
              (long)action.type, (long)TRAFFIC_ACTION_PASS);

    traffic_execute_action(&engine, &action);

    check_int("startup quarantine new syn sent adapter",
              g_test_adapter_send_count, 1);
    check_int("startup quarantine new syn not dropped",
              g_test_drop_count, 0);
}

static void test_startup_quarantine_allows_tracked_new_direct_tcp_non_syn(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_DIRECT;
    engine.tcp_relay_port = 34010;
    engine.udp_relay_port = 34011;

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_SYN);
    traffic_plan_packet(&engine, packet_observe(&ctx), &action);
    traffic_execute_action(&engine, &action);

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_ACK);
    traffic_plan_packet(&engine, packet_observe(&ctx), &action);

    check_int("startup quarantine tracked direct tcp non-syn passes",
              (long)action.type, (long)TRAFFIC_ACTION_PASS);

    traffic_execute_action(&engine, &action);

    check_int("startup quarantine tracked direct packets sent adapter",
              g_test_adapter_send_count, 2);
    check_int("startup quarantine tracked direct not sent mstcp",
              g_test_mstcp_send_count, 0);
    check_int("startup quarantine tracked direct not dropped",
              g_test_drop_count, 0);
}


static void test_udp_forward_frame_carries_destination(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);
    SOCKET receiver;
    SOCKET fwd_sock;
    struct sockaddr_in addr;
    int addr_len = sizeof(addr);
    struct timeval tv;
    uint8_t frame[128];
    int n;

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    receiver = socket(AF_INET, SOCK_DGRAM, 0);
    fwd_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (receiver < 0 || fwd_sock < 0) {
        fprintf(stderr, "FAIL frame test socket setup\n");
        failures++;
        return;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7F000001U);
    addr.sin_port = 0;
    if (bind(receiver, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        getsockname(receiver, (struct sockaddr *)&addr, &addr_len) != 0) {
        fprintf(stderr, "FAIL frame test bind\n");
        failures++;
        closesocket(receiver);
        closesocket(fwd_sock);
        return;
    }
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    engine.udp_fwd_sock = fwd_sock;
    engine.udp_relay_port = ntohs(addr.sin_port);

    set_udp_dns_context(&ctx, &buf, client_ip, 50000, server_ip, 443, 0xAABB);
    traffic_action_forward_udp_observed(&action, packet_observe(&ctx), "fwd");
    traffic_execute_action(&engine, &action);

    n = (int)recv(receiver, (char *)frame, sizeof(frame), 0);
    check_int("udp forward frame length", n, 12 + 2);
    if (n >= 12) {
        check_int("frame src ip", memcmp(frame, &client_ip, 4), 0);
        check_int("frame src port", (frame[4] << 8) | frame[5], 50000);
        check_int("frame dst ip", memcmp(frame + 6, &server_ip, 4), 0);
        check_int("frame dst port", (frame[10] << 8) | frame[11], 443);
    }
    if (n >= 14) {
        check_int("frame payload first byte", frame[12], 0xAA);
        check_int("frame payload second byte", frame[13], 0xBB);
    }
    check_int("udp forwarded counter", g_test_udp_forwarded_count, 1);

    closesocket(receiver);
    closesocket(fwd_sock);
}


static void test_udp_tracked_fast_path_skips_identity_and_policy(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_PROXY;
    engine.udp_relay_port = 34011;

    /* First datagram: full path - identity, policy, tracking. */
    set_udp_dns_context(&ctx, &buf, client_ip, 50000, server_ip, 5300, 0x1111);
    path_plan_policy(&engine, packet_observe(&ctx), &action);
    check_int("udp first datagram forwards",
              (long)action.type, (long)TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY);
    check_int("udp first datagram identity lookup",
              g_test_proc_lookup_udp_count, 1);
    check_int("udp first datagram tracks", g_test_conntrack_udp_proxy_track_count, 1);

    /* Second datagram on the tracked tuple: fused fast path only. */
    set_udp_dns_context(&ctx, &buf, client_ip, 50000, server_ip, 5300, 0x2222);
    path_plan_policy(&engine, packet_observe(&ctx), &action);
    check_int("udp tracked datagram forwards",
              (long)action.type, (long)TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY);
    check_int("udp tracked datagram skips identity lookup",
              g_test_proc_lookup_udp_count, 1);
    check_int("udp tracked datagram skips re-tracking",
              g_test_conntrack_udp_proxy_track_count, 1);
    check_int("udp tracked datagram uses fused role op",
              g_test_conntrack_role_udp_outbound_count >= 1, 1);
}

static void test_udp_policy_stays_per_destination(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    policy_rule_t rule;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server1 = htonl(0x08080808U);
    uint32_t server2 = htonl(0x09090909U);

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    /* Rule: proxy server1 only; everything else direct. */
    memset(&rule, 0, sizeof(rule));
    rule.id = 1;
    rule.enabled = 1;
    rule.decision = RULE_DECISION_PROXY;
    rule.protocol = RULE_PROTO_UDP;
    rule.process_any = 1;
    rule.port_any = 1;
    rule.ip_any = 0;
    rule.ip_ranges[0].start = 0x08080808U;
    rule.ip_ranges[0].end = 0x08080808U;
    rule.ip_range_count = 1;
    cfg.policy.rules = &rule;
    cfg.policy.rule_count = 1;
    cfg.policy.default_decision = RULE_DECISION_DIRECT;
    engine.udp_relay_port = 34011;

    /* server1 from port 50000: proxied and tracked. */
    set_udp_dns_context(&ctx, &buf, client_ip, 50000, server1, 5300, 0x1111);
    path_plan_policy(&engine, packet_observe(&ctx), &action);
    check_int("per-dst policy proxies server1",
              (long)action.type, (long)TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY);

    /* server2 from the SAME port: its own tuple, its own decision. */
    set_udp_dns_context(&ctx, &buf, client_ip, 50000, server2, 5300, 0x2222);
    path_plan_policy(&engine, packet_observe(&ctx), &action);
    check_int("per-dst policy directs server2",
              (long)action.type, (long)TRAFFIC_ACTION_PASS);
}


static void test_untracked_non_syn_drops_without_sync_refresh(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    dns_hijack_t dns_hijack;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server_ip = htonl(0x08080808U);
    int i;

    init_engine(&engine, &cfg, &dns_hijack);
    reset_counters();

    cfg.policy.default_decision = RULE_DECISION_PROXY;
    engine.tcp_relay_port = 34010;

    /* A burst of untracked non-SYN packets: every one drops fail-closed and
     * none may trigger the synchronous owner-table retry on a flow worker. */
    for (i = 0; i < 5; i++) {
        set_tcp_context(&ctx, &buf, client_ip, (uint16_t)(20000 + i),
                        server_ip, 443, TH_ACK);
        path_plan_policy(&engine, packet_observe(&ctx), &action);
        check_int("untracked non-syn drops",
                  (long)action.type, (long)TRAFFIC_ACTION_DROP);
    }
    check_int("untracked non-syn burst triggers no sync refresh",
              g_test_proc_lookup_tcp_retry_count, 0);
    check_int("untracked non-syn consults cached index",
              g_test_proc_lookup_tcp_count, 5);

    /* Self traffic with a cache hit still passes. */
    g_test_proc_lookup_tcp_pid = 42;
    g_test_proc_self_pid = 42;
    set_tcp_context(&ctx, &buf, client_ip, 20099, server_ip, 443, TH_ACK);
    path_plan_policy(&engine, packet_observe(&ctx), &action);
    check_int("untracked non-syn self cache hit passes",
              (long)action.type, (long)TRAFFIC_ACTION_PASS);
    check_int("self guard stays cache-only",
              g_test_proc_lookup_tcp_retry_count, 0);

    /* The SYN path keeps retry-with-refresh identity resolution. */
    g_test_proc_lookup_tcp_pid = 0;
    g_test_proc_self_pid = 0;
    set_tcp_context(&ctx, &buf, client_ip, 20100, server_ip, 443, TH_SYN);
    path_plan_policy(&engine, packet_observe(&ctx), &action);
    check_int("syn path still retries identity",
              g_test_proc_lookup_tcp_retry_count, 1);
}

int main(void) {
    test_loopback_plan_does_not_mutate_flag_before_execution();
    test_loopback_pass_is_routed_by_executor();
    test_direct_plan_keeps_packet_facts_stable_until_execution();
    test_batch_executor_groups_mstcp_driver_sends();
    test_batch_executor_groups_adapter_driver_sends_after_rewrite();
    test_batch_executor_preserves_mixed_action_outcomes();
    test_pass_planning_keeps_observation_snapshot();
    test_rewrite_execution_updates_frame_not_observation();
    test_dns_planning_keeps_txid_payload_observation();
    test_return_planning_keeps_observation_snapshot();
    test_direct_tcp_uses_role_contract_and_tracks_non_syn();
    test_tcp_proxy_uses_role_contract_creation();
    test_udp_proxy_uses_role_contract_creation();
    test_udp_forward_frame_carries_destination();
    test_udp_tracked_fast_path_skips_identity_and_policy();
    test_udp_policy_stays_per_destination();
    test_untracked_non_syn_drops_without_sync_refresh();
    test_tcp_dns_uses_role_contract_creation();
    test_relay_consumes_tcp_and_udp_role_contracts();
    test_tcp_proxy_plan_does_not_mutate_packet_until_execution();
    test_tcp_proxy_rewrite_applies_during_execution();
    test_tracked_tcp_proxy_non_syn_waits_for_executor_rewrite();
    test_tcp_proxy_return_waits_for_executor_rewrite();
    test_tcp_proxy_return_missing_state_drops_closed();
    test_udp_proxy_return_waits_for_executor_rewrite();
    test_udp_proxy_return_missing_state_drops_closed();
    test_udp_dns_query_waits_for_executor_rewrite();
    test_udp_dns_response_waits_for_executor_rewrite();
    test_loopback_udp_dns_query_forwards_without_packet_mutation();
    test_loopback_dns_forward_failure_drops_closed();
    test_loopback_dns_response_injection_uses_executor_send_path();
    test_loopback_dns_malformed_response_injection_drops_closed();
    test_loopback_dns_response_send_failure_fails_closed();
    test_tcp_dns_query_waits_for_executor_rewrite();
    test_loopback_tcp_dns_query_routes_to_mstcp_on_execute();
    test_public_plan_non_proxyable_direct_uses_executor_owner();
    test_public_plan_untracked_proxy_non_syn_drops_closed();
    test_startup_quarantine_discards_preexisting_external_direct_tcp();
    test_startup_quarantine_allows_new_direct_tcp_syn();
    test_startup_quarantine_allows_tracked_new_direct_tcp_non_syn();

    if (failures > 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    fprintf(stderr, "all tests passed\n");
    return 0;
}
