/*
 * Conntrack fused role operation tests - run against the real conntrack.c.
 *
 * Role lookups must fuse TTL refresh into the lookup pass, own entry-pair
 * liveness, and return narrow snapshots without process_name.
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "app/log.h"
#include "conntrack/conntrack.h"

int g_test_windows_create_thread_count = 0;
LPTHREAD_START_ROUTINE g_test_windows_thread_procs[64];
LPVOID g_test_windows_thread_params[64];
int g_test_windows_set_event_count = 0;
HANDLE g_test_windows_set_event_handles[128];
int g_test_windows_wait_count = 0;
int g_test_windows_sleep_count = 0;
uint64_t g_test_windows_tick_ms = 0;
int g_test_windows_srw_exclusive_count = 0;
int g_test_winsock_ioctl_count = 0;

static int failures = 0;

int log_is_enabled(log_level_t level) {
    (void)level;
    return 0;
}

void log_write(log_level_t level, const char *fmt, ...) {
    (void)level;
    (void)fmt;
}

static void check_int(const char *name, long actual, long expected) {
    if (actual != expected) {
        fprintf(stderr, "FAIL %s: got %ld expected %ld\n", name, actual, expected);
        failures++;
    }
}

static void check_u64(const char *name, uint64_t actual, uint64_t expected) {
    if (actual != expected) {
        fprintf(stderr, "FAIL %s: got %llu expected %llu\n", name,
                (unsigned long long)actual, (unsigned long long)expected);
        failures++;
    }
}

/* White-box helper: read an entry's timestamp by key (struct is public). */
static int find_entry_timestamp(conntrack_t *ct, uint32_t key_src_ip,
                                uint16_t key_src_port, uint32_t key_dst_ip,
                                uint16_t key_dst_port, uint8_t protocol,
                                uint64_t *timestamp_out) {
    for (size_t i = 0; i < ct->bucket_count; i++) {
        for (conntrack_entry_t *e = ct->buckets[i]; e; e = e->next) {
            if (e->key_src_ip == key_src_ip && e->src_port == key_src_port &&
                e->key_dst_ip == key_dst_ip && e->key_dst_port == key_dst_port &&
                e->protocol == protocol) {
                if (timestamp_out) *timestamp_out = e->timestamp;
                return 1;
            }
        }
    }
    return 0;
}

static const uint32_t CLIENT_IP = 0x0A000002U;
static const uint32_t SERVER_IP = 0x08080808U;

static void test_tcp_outbound_role_fuses_refresh(void) {
    conntrack_t ct;
    conntrack_tcp_proxy_flow_t flow;
    conntrack_role_snapshot_t snap;
    uint16_t relay_src_port = 0;
    uint64_t ts = 0;

    g_test_windows_tick_ms = 1000;
    if (conntrack_init(&ct) != ERR_OK) {
        fprintf(stderr, "FAIL conntrack_init\n");
        failures++;
        return;
    }

    memset(&flow, 0, sizeof(flow));
    flow.client_ip = CLIENT_IP;
    flow.client_port = 12345;
    flow.server_ip = SERVER_IP;
    flow.server_port = 443;
    flow.relay_port = 34010;
    flow.proposed_relay_src_port = 40000;
    check_int("tcp proxy track",
              conntrack_track_tcp_proxy(&ct, &flow, &relay_src_port), ERR_OK);
    check_int("tcp proxy relay src port", relay_src_port, 40000);

    g_test_windows_tick_ms = 5000;
    memset(&snap, 0, sizeof(snap));
    check_int("tcp outbound role hit",
              conntrack_role_tcp_outbound(&ct, CLIENT_IP, 12345,
                                          SERVER_IP, 443, &snap), ERR_OK);
    check_int("tcp outbound snapshot client ip", (long)snap.client_ip,
              (long)CLIENT_IP);
    check_int("tcp outbound snapshot client port", snap.client_port, 12345);
    check_int("tcp outbound snapshot orig dst port", snap.orig_dst_port, 443);
    check_int("tcp outbound snapshot relay src port", snap.relay_src_port, 40000);

    if (!find_entry_timestamp(&ct, CLIENT_IP, 12345, SERVER_IP, 443,
                              WTP_IPPROTO_TCP, &ts)) {
        fprintf(stderr, "FAIL tcp outbound entry missing\n");
        failures++;
    }
    check_u64("tcp outbound fused refresh", ts, 5000);

    check_int("tcp outbound role miss",
              conntrack_role_tcp_outbound(&ct, CLIENT_IP, 1, SERVER_IP, 2,
                                          &snap), ERR_NOT_FOUND);

    conntrack_shutdown(&ct);
}

static void test_tcp_return_role_refreshes_pair(void) {
    conntrack_t ct;
    conntrack_tcp_proxy_flow_t flow;
    conntrack_role_snapshot_t snap;
    uint16_t relay_src_port = 0;
    uint64_t ts_a = 0;
    uint64_t ts_b = 0;

    g_test_windows_tick_ms = 1000;
    if (conntrack_init(&ct) != ERR_OK) {
        fprintf(stderr, "FAIL conntrack_init\n");
        failures++;
        return;
    }

    memset(&flow, 0, sizeof(flow));
    flow.client_ip = CLIENT_IP;
    flow.client_port = 12345;
    flow.server_ip = SERVER_IP;
    flow.server_port = 443;
    flow.relay_port = 34010;
    flow.proposed_relay_src_port = 40000;
    conntrack_track_tcp_proxy(&ct, &flow, &relay_src_port);

    g_test_windows_tick_ms = 9000;
    memset(&snap, 0, sizeof(snap));
    check_int("tcp return role hit",
              conntrack_role_tcp_return(&ct, SERVER_IP, 40000,
                                        CLIENT_IP, 34010, &snap), ERR_OK);
    check_int("tcp return snapshot client ip", (long)snap.client_ip,
              (long)CLIENT_IP);
    check_int("tcp return snapshot client port", snap.client_port, 12345);
    check_int("tcp return snapshot orig dst ip", (long)snap.orig_dst_ip,
              (long)SERVER_IP);
    check_int("tcp return snapshot orig dst port", snap.orig_dst_port, 443);

    find_entry_timestamp(&ct, CLIENT_IP, 12345, SERVER_IP, 443,
                         WTP_IPPROTO_TCP, &ts_a);
    find_entry_timestamp(&ct, SERVER_IP, 40000, CLIENT_IP, 34010,
                         WTP_IPPROTO_TCP, &ts_b);
    check_u64("tcp return refreshes B", ts_b, 9000);
    check_u64("tcp return refreshes paired A", ts_a, 9000);

    conntrack_shutdown(&ct);
}

static void test_udp_roles_keep_one_way_flow_pair_alive(void) {
    conntrack_t ct;
    conntrack_udp_proxy_flow_t flow;
    conntrack_role_snapshot_t snap;
    uint32_t server2 = 0x09090909U;
    uint64_t ts_a = 0;
    uint64_t ts_a2 = 0;
    uint64_t ts_b = 0;

    g_test_windows_tick_ms = 1000;
    if (conntrack_init(&ct) != ERR_OK) {
        fprintf(stderr, "FAIL conntrack_init\n");
        failures++;
        return;
    }

    memset(&flow, 0, sizeof(flow));
    flow.client_ip = CLIENT_IP;
    flow.client_port = 50000;
    flow.server_ip = SERVER_IP;
    flow.server_port = 53;
    check_int("udp proxy track", conntrack_track_udp_proxy(&ct, &flow), ERR_OK);

    /* Second destination from the same client port: its own outbound entry. */
    flow.server_ip = server2;
    flow.server_port = 8053;
    check_int("udp proxy track second tuple",
              conntrack_track_udp_proxy(&ct, &flow), ERR_OK);

    /* Outbound entries are keyed by the full tuple. */
    if (!find_entry_timestamp(&ct, CLIENT_IP, 50000, SERVER_IP, 53,
                              WTP_IPPROTO_UDP, &ts_a) ||
        !find_entry_timestamp(&ct, CLIENT_IP, 50000, server2, 8053,
                              WTP_IPPROTO_UDP, &ts_a2)) {
        fprintf(stderr, "FAIL udp outbound entries not full-tuple keyed\n");
        failures++;
        conntrack_shutdown(&ct);
        return;
    }

    /* One-way outbound traffic must keep its own pair alive - and only it. */
    g_test_windows_tick_ms = 6000;
    memset(&snap, 0, sizeof(snap));
    check_int("udp outbound role hit",
              conntrack_role_udp_outbound(&ct, CLIENT_IP, 50000,
                                          SERVER_IP, 53, &snap), ERR_OK);
    check_int("udp outbound snapshot orig dst ip", (long)snap.orig_dst_ip,
              (long)SERVER_IP);
    check_int("udp outbound snapshot orig dst port", snap.orig_dst_port, 53);

    find_entry_timestamp(&ct, CLIENT_IP, 50000, SERVER_IP, 53,
                         WTP_IPPROTO_UDP, &ts_a);
    find_entry_timestamp(&ct, CLIENT_IP, 50000, server2, 8053,
                         WTP_IPPROTO_UDP, &ts_a2);
    find_entry_timestamp(&ct, SERVER_IP, 50000, 0, 0, WTP_IPPROTO_UDP, &ts_b);
    check_u64("udp outbound refreshes its tuple", ts_a, 6000);
    check_u64("udp outbound refreshes paired B", ts_b, 6000);
    check_u64("udp outbound leaves other tuple alone", ts_a2, 1000);

    g_test_windows_tick_ms = 8000;
    memset(&snap, 0, sizeof(snap));
    check_int("udp return role hit",
              conntrack_role_udp_return(&ct, SERVER_IP, 50000, &snap), ERR_OK);
    check_int("udp return snapshot client ip", (long)snap.client_ip,
              (long)CLIENT_IP);
    check_int("udp return snapshot client port", snap.client_port, 50000);

    find_entry_timestamp(&ct, CLIENT_IP, 50000, SERVER_IP, 53,
                         WTP_IPPROTO_UDP, &ts_a);
    find_entry_timestamp(&ct, SERVER_IP, 50000, 0, 0, WTP_IPPROTO_UDP, &ts_b);
    check_u64("udp return refreshes B", ts_b, 8000);
    check_u64("udp return refreshes paired full-tuple A", ts_a, 8000);

    check_int("udp outbound role miss for untracked tuple",
              conntrack_role_udp_outbound(&ct, CLIENT_IP, 50000,
                                          SERVER_IP, 9999, &snap),
              ERR_NOT_FOUND);

    conntrack_shutdown(&ct);
}

static void test_tcp_dns_return_role_refreshes_entry(void) {
    conntrack_t ct;
    conntrack_tcp_dns_flow_t flow;
    conntrack_role_snapshot_t snap;
    uint64_t ts = 0;
    uint32_t original_dns_ip = 0x01010101U;
    uint32_t redirect_ip = SERVER_IP;

    g_test_windows_tick_ms = 1000;
    if (conntrack_init(&ct) != ERR_OK) {
        fprintf(stderr, "FAIL conntrack_init\n");
        failures++;
        return;
    }

    memset(&flow, 0, sizeof(flow));
    flow.client_ip = CLIENT_IP;
    flow.client_port = 12345;
    flow.original_dns_ip = original_dns_ip;
    flow.original_dns_port = 53;
    flow.redirect_ip = redirect_ip;
    flow.redirect_port = 5353;
    flow.loopback_redirect = 0;
    check_int("tcp dns track", conntrack_track_tcp_dns(&ct, &flow), ERR_OK);

    g_test_windows_tick_ms = 4000;
    memset(&snap, 0, sizeof(snap));
    check_int("tcp dns return role hit",
              conntrack_role_tcp_dns_return(&ct, redirect_ip, 5353,
                                            CLIENT_IP, 12345, &snap), ERR_OK);
    check_int("tcp dns snapshot orig dns ip", (long)snap.orig_dst_ip,
              (long)original_dns_ip);
    check_int("tcp dns snapshot orig dns port", snap.orig_dst_port, 53);
    check_int("tcp dns snapshot client ip", (long)snap.client_ip,
              (long)CLIENT_IP);
    check_int("tcp dns snapshot client port", snap.client_port, 12345);

    find_entry_timestamp(&ct, CLIENT_IP, 12345, redirect_ip, 5353,
                         WTP_IPPROTO_TCP, &ts);
    check_u64("tcp dns return fused refresh", ts, 4000);

    conntrack_shutdown(&ct);
}

static void test_relay_pair_refresh_op_refreshes_both_entries(void) {
    conntrack_t ct;
    conntrack_tcp_proxy_flow_t flow;
    conntrack_entry_t entry;
    uint16_t relay_src_port = 0;
    uint64_t ts_a = 0;
    uint64_t ts_b = 0;

    g_test_windows_tick_ms = 1000;
    if (conntrack_init(&ct) != ERR_OK) {
        fprintf(stderr, "FAIL conntrack_init\n");
        failures++;
        return;
    }

    memset(&flow, 0, sizeof(flow));
    flow.client_ip = CLIENT_IP;
    flow.client_port = 12345;
    flow.server_ip = SERVER_IP;
    flow.server_port = 443;
    flow.relay_port = 34010;
    flow.proposed_relay_src_port = 40000;
    conntrack_track_tcp_proxy(&ct, &flow, &relay_src_port);

    /* Relay connection setup still uses the full-entry snapshot. */
    check_int("relay setup full lookup",
              conntrack_get_tcp_proxy_return(&ct, SERVER_IP, 40000,
                                             CLIENT_IP, 34010, &entry), ERR_OK);

    g_test_windows_tick_ms = 21000;
    conntrack_role_refresh_tcp_pair(&ct, &entry);

    find_entry_timestamp(&ct, CLIENT_IP, 12345, SERVER_IP, 443,
                         WTP_IPPROTO_TCP, &ts_a);
    find_entry_timestamp(&ct, SERVER_IP, 40000, CLIENT_IP, 34010,
                         WTP_IPPROTO_TCP, &ts_b);
    check_u64("relay pair refresh updates A", ts_a, 21000);
    check_u64("relay pair refresh updates B", ts_b, 21000);

    conntrack_shutdown(&ct);
}

static void test_role_snapshot_is_narrow(void) {
    /* No process_name on the per-packet path: the snapshot stays scalar. */
    check_int("role snapshot stays narrow",
              sizeof(conntrack_role_snapshot_t) <= 16, 1);
}

int main(void) {
    test_tcp_outbound_role_fuses_refresh();
    test_tcp_return_role_refreshes_pair();
    test_udp_roles_keep_one_way_flow_pair_alive();
    test_tcp_dns_return_role_refreshes_entry();
    test_relay_pair_refresh_op_refreshes_both_entries();
    test_role_snapshot_is_narrow();

    if (failures > 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    fprintf(stderr, "all tests passed\n");
    return 0;
}
