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
extern int g_test_drop_count;
extern int g_test_conntrack_get_full_key_hit;
extern int g_test_conntrack_tcp_proxy_outbound_hit;
extern int g_test_conntrack_tcp_proxy_return_hit;
extern int g_test_conntrack_tcp_proxy_outbound_touch_count;
extern int g_test_conntrack_tcp_proxy_return_touch_count;
extern int g_test_conntrack_udp_proxy_outbound_hit;
extern int g_test_conntrack_udp_proxy_return_hit;
extern int g_test_conntrack_udp_proxy_outbound_touch_count;
extern int g_test_conntrack_udp_proxy_return_touch_count;
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
    g_test_drop_count = 0;
    g_test_conntrack_get_full_key_hit = 0;
    g_test_conntrack_tcp_proxy_outbound_hit = 0;
    g_test_conntrack_tcp_proxy_return_hit = 0;
    g_test_conntrack_tcp_proxy_outbound_touch_count = 0;
    g_test_conntrack_tcp_proxy_return_touch_count = 0;
    g_test_conntrack_udp_proxy_outbound_hit = 0;
    g_test_conntrack_udp_proxy_return_hit = 0;
    g_test_conntrack_udp_proxy_outbound_touch_count = 0;
    g_test_conntrack_udp_proxy_return_touch_count = 0;
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
    path_plan_bypass(&engine, &ctx, &action, "self-proxy direct");

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
    path_plan_bypass(&engine, &ctx, &action, "self-proxy direct");
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
    path_plan_bypass(&engine, &ctx, &action, "self-proxy direct");

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

    path_plan_policy(&engine, &ctx, &action);

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

    path_plan_policy(&engine, &ctx, &action);
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

    path_plan_policy(&engine, &ctx, &action);

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

    path_plan_return(&engine, &ctx, 1, &action);

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
    check_int("tcp return outbound conntrack touched",
              g_test_conntrack_tcp_proxy_outbound_touch_count, 1);
    check_int("tcp return relay conntrack touched",
              g_test_conntrack_tcp_proxy_return_touch_count, 1);
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

    path_plan_return(&engine, &ctx, 1, &action);

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

    path_plan_return(&engine, &ctx, 0, &action);

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
    check_int("udp return outbound conntrack touched",
              g_test_conntrack_udp_proxy_outbound_touch_count, 1);
    check_int("udp return relay conntrack touched",
              g_test_conntrack_udp_proxy_return_touch_count, 1);
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

    path_plan_return(&engine, &ctx, 0, &action);

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

    dns_plan_udp_query(&engine, &ctx, &action);

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

    dns_plan_inbound_or_response(&engine, &ctx, 1, &action);

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

    dns_plan_udp_query(&engine, &ctx, &action);

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

    dns_plan_tcp_query(&engine, &ctx, &action);

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

    dns_plan_tcp_query(&engine, &ctx, &action);

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

    traffic_plan_packet(&engine, &ctx, &action);

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

    traffic_plan_packet(&engine, &ctx, &action);

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

    traffic_plan_packet(&engine, &ctx, &action);

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

    traffic_plan_packet(&engine, &ctx, &action);

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
    traffic_plan_packet(&engine, &ctx, &action);
    traffic_execute_action(&engine, &action);

    set_tcp_context(&ctx, &buf, client_ip, 12345, server_ip, 443, TH_ACK);
    traffic_plan_packet(&engine, &ctx, &action);

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

int main(void) {
    test_loopback_plan_does_not_mutate_flag_before_execution();
    test_loopback_pass_is_routed_by_executor();
    test_direct_plan_keeps_packet_facts_stable_until_execution();
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
