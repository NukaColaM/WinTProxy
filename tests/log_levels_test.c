#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "app/config.h"
#include "app/log.h"
#include "core/constants.h"
#include "core/util.h"
#include "flow/action.h"
#include "dns/hijack.h"
#include "ndisapi/adapter.h"
#include "net/headers.h"
#include "path/bypass.h"
#include "path/proxy.h"

extern log_level_t g_test_log_enabled_level;
extern log_level_t g_test_log_last_level;
extern char g_test_log_last_message[512];
extern int g_test_log_write_count;
extern void test_reset_conntrack_stub_state(void);

static int failures = 0;

static void reset_log_capture(log_level_t enabled_level) {
    g_test_log_enabled_level = enabled_level;
    g_test_log_last_level = LOG_LEVEL_COUNT;
    g_test_log_last_message[0] = '\0';
    g_test_log_write_count = 0;
    test_reset_conntrack_stub_state();
}

static void check_int(const char *name, long got, long want) {
    if (got != want) {
        fprintf(stderr, "FAIL %s: got %ld want %ld\n", name, got, want);
        failures++;
    }
}

static void check_contains(const char *name, const char *haystack,
                           const char *needle) {
    if (!haystack || !needle || !strstr(haystack, needle)) {
        fprintf(stderr, "FAIL %s: missing '%s' in '%s'\n",
                name, needle ? needle : "(null)", haystack ? haystack : "(null)");
        failures++;
    }
}

static void init_engine(ndisapi_engine_t *engine, app_config_t *cfg) {
    memset(engine, 0, sizeof(*engine));
    memset(cfg, 0, sizeof(*cfg));
    engine->config = cfg;
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

static void test_policy_route_decision_is_debug_visible(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;

    init_engine(&engine, &cfg);
    cfg.policy.default_decision = RULE_DECISION_PROXY;
    engine.udp_relay_port = 34011;
    reset_log_capture(LOG_DEBUG);

    set_udp_context(&ctx, &buf,
                    htonl(0x0A000002U), 12345,
                    htonl(0x08080808U), 443);

    path_plan_policy(&engine, packet_observe(&ctx), &action);

    check_int("policy route logged once at debug",
              g_test_log_write_count, 1);
    check_int("policy route log level",
              (long)g_test_log_last_level, (long)LOG_DEBUG);
    check_contains("policy route log text",
                   g_test_log_last_message, "via relay");
}

static void test_bypass_decision_is_debug_visible(void) {
    app_config_t cfg;
    ndisapi_engine_t engine;
    packet_ctx_t ctx;
    traffic_action_t action;
    INTERMEDIATE_BUFFER buf;

    init_engine(&engine, &cfg);
    reset_log_capture(LOG_DEBUG);

    set_udp_context(&ctx, &buf,
                    htonl(0x0A000002U), 12345,
                    htonl(0xE00000FBU), 5353);

    path_plan_bypass(&engine, packet_observe(&ctx), &action, "multicast");

    check_int("bypass route logged once at debug",
              g_test_log_write_count, 1);
    check_int("bypass route log level",
              (long)g_test_log_last_level, (long)LOG_DEBUG);
    check_contains("bypass route log text",
                   g_test_log_last_message, "DIRECT [");
}

static void test_dns_forward_recv_normal_errors_are_silent(void) {
    check_int("dns fwd timeout is silent",
              dns_hijack_should_log_forward_recv_error(10060), 0);
    check_int("dns fwd socket interrupt is silent",
              dns_hijack_should_log_forward_recv_error(10004), 0);
    check_int("dns fwd closed socket is silent",
              dns_hijack_should_log_forward_recv_error(10038), 0);
    check_int("dns fwd unexpected error is trace-worthy",
              dns_hijack_should_log_forward_recv_error(10054), 1);
}

int main(void) {
    test_policy_route_decision_is_debug_visible();
    test_bypass_decision_is_debug_visible();
    test_dns_forward_recv_normal_errors_are_silent();

    if (failures > 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    fprintf(stderr, "all tests passed\n");
    return 0;
}
