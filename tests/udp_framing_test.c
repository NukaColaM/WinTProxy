/*
 * UDP destination framing tests - run the real relay datagram handlers and
 * the real SOCKS5 wrap/unwrap over loopback sockets.
 *
 * Contract: the executor-to-relay frame carries the datagram's destination
 * (src_ip src_port dst_ip dst_port payload); the relay wraps toward the
 * framed destination and routes responses by the unwrapped SOCKS source, so
 * one client port talking to several servers is proxied correctly both ways.
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#include "app/log.h"
#include "conntrack/conntrack.h"
#include "relay/udp.h"
#include "relay/socks5.h"

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

static SOCKET bind_loopback(uint32_t ip_net, uint16_t port_host,
                            struct sockaddr_in *bound) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    int addr_len = sizeof(addr);
    struct timeval tv;

    if (s < 0) return INVALID_SOCKET;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip_net;
    addr.sin_port = htons(port_host);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        getsockname(s, (struct sockaddr *)&addr, &addr_len) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    if (bound) *bound = addr;
    return s;
}

/* Frame format produced by the executor: src(6) dst(6) payload. */
static int build_frame(uint8_t *out, uint32_t src_ip_net, uint16_t src_port,
                       uint32_t dst_ip_net, uint16_t dst_port,
                       const uint8_t *payload, int payload_len) {
    memcpy(out, &src_ip_net, 4);
    out[4] = (uint8_t)(src_port >> 8);
    out[5] = (uint8_t)(src_port & 0xFF);
    memcpy(out + 6, &dst_ip_net, 4);
    out[10] = (uint8_t)(dst_port >> 8);
    out[11] = (uint8_t)(dst_port & 0xFF);
    memcpy(out + 12, payload, (size_t)payload_len);
    return 12 + payload_len;
}

static void setup_relay(udp_relay_t *relay, conntrack_t *ct) {
    memset(relay, 0, sizeof(*relay));
    relay->conntrack = ct;
    relay->session_capacity = 8;
    relay->bucket_count = 16;
    InitializeSRWLock(&relay->session_lock);
    relay->sessions = (udp_session_t *)calloc(relay->session_capacity,
                                              sizeof(relay->sessions[0]));
    relay->session_buckets = (int *)malloc(relay->bucket_count *
                                           sizeof(relay->session_buckets[0]));
    for (size_t i = 0; i < relay->session_capacity; i++) {
        relay->sessions[i].ctrl_sock = INVALID_SOCKET;
        relay->sessions[i].relay_sock = INVALID_SOCKET;
        relay->sessions[i].next_index = -1;
        relay->sessions[i].bucket = -1;
    }
    for (size_t i = 0; i < relay->bucket_count; i++) {
        relay->session_buckets[i] = -1;
    }
}

/* Place session 0 so find_session locates it from any hash bucket. */
static void fabricate_session(udp_relay_t *relay, uint32_t client_ip,
                              uint16_t client_port, SOCKET relay_sock,
                              struct sockaddr_in relay_addr) {
    udp_session_t *s = &relay->sessions[0];

    s->active = 1;
    s->client_ip = client_ip;
    s->client_port = client_port;
    s->ctrl_sock = INVALID_SOCKET;
    s->relay_sock = relay_sock;
    s->relay_addr = relay_addr;
    s->last_activity = g_test_windows_tick_ms;
    s->bucket = 0;
    s->next_index = -1;
    for (size_t i = 0; i < relay->bucket_count; i++) {
        relay->session_buckets[i] = 0;
    }
}

static void teardown_relay(udp_relay_t *relay) {
    if (relay->local_sock != INVALID_SOCKET && relay->local_sock >= 0) {
        closesocket(relay->local_sock);
    }
    free(relay->sessions);
    free(relay->session_buckets);
}

static void test_relay_wraps_each_datagram_to_its_framed_destination(void) {
    conntrack_t ct;
    udp_relay_t relay;
    conntrack_udp_proxy_flow_t flow;
    struct sockaddr_in fake_proxy_addr;
    SOCKET fake_proxy;
    SOCKET relay_sock;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server1 = inet_addr("127.0.0.60");
    uint32_t server2 = inet_addr("127.0.0.61");
    uint8_t frame[64];
    uint8_t send_buf[512];
    uint8_t wire[512];
    int frame_len;
    int n;

    g_test_windows_tick_ms = 1000;
    if (conntrack_init(&ct) != ERR_OK) {
        fprintf(stderr, "FAIL conntrack_init\n");
        failures++;
        return;
    }
    setup_relay(&relay, &ct);
    relay.local_sock = bind_loopback(htonl(0x7F000001U), 0, NULL);

    fake_proxy = bind_loopback(htonl(0x7F000001U), 0, &fake_proxy_addr);
    relay_sock = bind_loopback(htonl(0x7F000001U), 0, NULL);
    if (fake_proxy == INVALID_SOCKET || relay_sock == INVALID_SOCKET) {
        fprintf(stderr, "FAIL framing test socket setup\n");
        failures++;
        return;
    }
    fabricate_session(&relay, client_ip, 50000, relay_sock, fake_proxy_addr);

    /* Both tuples are tracked (policy proxied both); the gate is per
     * tuple, while the wrap destination comes from the frame. */
    memset(&flow, 0, sizeof(flow));
    flow.client_ip = client_ip;
    flow.client_port = 50000;
    flow.server_ip = server1;
    flow.server_port = 53;
    conntrack_track_udp_proxy(&ct, &flow);
    flow.server_ip = server2;
    flow.server_port = 8053;
    conntrack_track_udp_proxy(&ct, &flow);

    /* A datagram framed for the second destination must be wrapped toward
     * the framed destination, not another tuple's destination. */
    frame_len = build_frame(frame, client_ip, 50000, server2, 8053,
                            (const uint8_t *)"BB", 2);
    udp_relay_test_handle_client_datagram(&relay, frame, frame_len,
                                          send_buf, (int)sizeof(send_buf));

    n = (int)recv(fake_proxy, (char *)wire, sizeof(wire), 0);
    if (n <= 0) {
        fprintf(stderr, "FAIL framed wrap: nothing reached the proxy\n");
        failures++;
    } else {
        uint32_t wrapped_dst_ip = 0;
        uint16_t wrapped_dst_port = 0;
        const uint8_t *payload = NULL;
        int payload_len = 0;

        check_int("framed wrap unwraps",
                  socks5_udp_unwrap(wire, n, &wrapped_dst_ip,
                                    &wrapped_dst_port, &payload,
                                    &payload_len), ERR_OK);
        check_int("wrap targets framed destination ip",
                  (long)wrapped_dst_ip, (long)server2);
        check_int("wrap targets framed destination port", wrapped_dst_port, 8053);
        check_int("wrap payload length", payload_len, 2);
        if (payload_len == 2) {
            check_int("wrap payload content", memcmp(payload, "BB", 2), 0);
        }
    }

    /* Untracked tuples stay dropped (conntrack remains the per-tuple gate),
     * even when the client port itself is tracked for other servers. */
    {
        LONG64 dropped_before = relay.counters.dropped_datagrams;
        frame_len = build_frame(frame, client_ip, 50000,
                                inet_addr("127.0.0.62"), 7000,
                                (const uint8_t *)"CC", 2);
        udp_relay_test_handle_client_datagram(&relay, frame, frame_len,
                                              send_buf, (int)sizeof(send_buf));
        check_int("untracked client port dropped",
                  (long)(relay.counters.dropped_datagrams - dropped_before), 1);
    }

    closesocket(fake_proxy);
    closesocket(relay_sock);
    teardown_relay(&relay);
    conntrack_shutdown(&ct);
}

static void test_relay_routes_response_by_unwrapped_source(void) {
    conntrack_t ct;
    udp_relay_t relay;
    conntrack_udp_proxy_flow_t flow;
    struct sockaddr_in fake_proxy_addr;
    struct sockaddr_in relay_sock_addr;
    SOCKET fake_proxy;
    SOCKET relay_sock;
    SOCKET responder_receiver;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server1 = inet_addr("127.0.0.60");
    uint32_t server2 = inet_addr("127.0.0.61");
    uint8_t wrapped[256];
    uint8_t recv_buf[512];
    uint8_t out[64];
    int wrapped_len;
    int addr_len;
    int n;

    g_test_windows_tick_ms = 1000;
    if (conntrack_init(&ct) != ERR_OK) {
        fprintf(stderr, "FAIL conntrack_init\n");
        failures++;
        return;
    }
    setup_relay(&relay, &ct);
    relay.local_sock = bind_loopback(htonl(0x7F000001U), 0, NULL);

    fake_proxy = bind_loopback(htonl(0x7F000001U), 0, &fake_proxy_addr);
    relay_sock = bind_loopback(htonl(0x7F000001U), 0, NULL);
    /* The client port on the second server's address: only correct
     * source-based routing delivers here. */
    responder_receiver = bind_loopback(server2, 50000, NULL);
    if (fake_proxy == INVALID_SOCKET || relay_sock == INVALID_SOCKET ||
        responder_receiver == INVALID_SOCKET) {
        fprintf(stderr, "FAIL response routing socket setup\n");
        failures++;
        return;
    }
    fabricate_session(&relay, client_ip, 50000, relay_sock, fake_proxy_addr);

    /* Conntrack knows the FIRST destination; the response comes from the
     * second. Routing must follow the SOCKS source, not the entry. */
    memset(&flow, 0, sizeof(flow));
    flow.client_ip = client_ip;
    flow.client_port = 50000;
    flow.server_ip = server1;
    flow.server_port = 53;
    conntrack_track_udp_proxy(&ct, &flow);

    wrapped_len = socks5_udp_wrap(wrapped, (int)sizeof(wrapped),
                                  server2, 50000,
                                  (const uint8_t *)"RR", 2);
    if (wrapped_len <= 0) {
        fprintf(stderr, "FAIL response routing wrap\n");
        failures++;
        return;
    }
    addr_len = sizeof(relay_sock_addr);
    getsockname(relay_sock, (struct sockaddr *)&relay_sock_addr, &addr_len);
    sendto(fake_proxy, (const char *)wrapped, wrapped_len, 0,
           (struct sockaddr *)&relay_sock_addr, sizeof(relay_sock_addr));

    udp_relay_test_handle_proxy_datagram(&relay, relay_sock, fake_proxy_addr,
                                         client_ip, 50000, 0,
                                         relay.sessions[0].generation,
                                         recv_buf);

    n = (int)recv(responder_receiver, (char *)out, sizeof(out), 0);
    check_int("response routed to unwrapped source address", n, 2);
    if (n == 2) {
        check_int("response payload content", memcmp(out, "RR", 2), 0);
    }

    closesocket(fake_proxy);
    closesocket(relay_sock);
    closesocket(responder_receiver);
    teardown_relay(&relay);
    conntrack_shutdown(&ct);
}


static void test_datagram_path_avoids_probe_and_exclusive_locks(void) {
    conntrack_t ct;
    udp_relay_t relay;
    conntrack_udp_proxy_flow_t flow;
    struct sockaddr_in fake_proxy_addr;
    struct sockaddr_in relay_sock_addr;
    SOCKET fake_proxy;
    SOCKET relay_sock;
    SOCKET ctrl_sock;
    SOCKET responder_receiver;
    uint32_t client_ip = htonl(0x0A000002U);
    uint32_t server1 = inet_addr("127.0.0.60");
    uint8_t frame[64];
    uint8_t send_buf[512];
    uint8_t wire[512];
    uint8_t recv_buf[512];
    int frame_len;
    int addr_len;
    int n;

    g_test_windows_tick_ms = 1000;
    if (conntrack_init(&ct) != ERR_OK) {
        fprintf(stderr, "FAIL conntrack_init\n");
        failures++;
        return;
    }
    setup_relay(&relay, &ct);
    relay.local_sock = bind_loopback(htonl(0x7F000001U), 0, NULL);

    fake_proxy = bind_loopback(htonl(0x7F000001U), 0, &fake_proxy_addr);
    relay_sock = bind_loopback(htonl(0x7F000001U), 0, NULL);
    ctrl_sock = bind_loopback(htonl(0x7F000001U), 0, NULL);
    responder_receiver = bind_loopback(server1, 50000, NULL);
    if (fake_proxy == INVALID_SOCKET || relay_sock == INVALID_SOCKET ||
        ctrl_sock == INVALID_SOCKET || responder_receiver == INVALID_SOCKET) {
        fprintf(stderr, "FAIL slim path socket setup\n");
        failures++;
        return;
    }
    fabricate_session(&relay, client_ip, 50000, relay_sock, fake_proxy_addr);
    relay.sessions[0].ctrl_sock = ctrl_sock;

    memset(&flow, 0, sizeof(flow));
    flow.client_ip = client_ip;
    flow.client_port = 50000;
    flow.server_ip = server1;
    flow.server_port = 53;
    conntrack_track_udp_proxy(&ct, &flow);

    /* Outbound datagram: no liveness probe, no exclusive session lock. */
    g_test_winsock_ioctl_count = 0;
    g_test_windows_srw_exclusive_count = 0;
    frame_len = build_frame(frame, client_ip, 50000, server1, 53,
                            (const uint8_t *)"DD", 2);
    udp_relay_test_handle_client_datagram(&relay, frame, frame_len,
                                          send_buf, (int)sizeof(send_buf));
    check_int("outbound datagram skips liveness probe",
              g_test_winsock_ioctl_count, 0);
    check_int("outbound datagram takes no exclusive lock",
              g_test_windows_srw_exclusive_count, 0);
    n = (int)recv(fake_proxy, (char *)wire, sizeof(wire), 0);
    check_int("outbound datagram still forwards", n > 0, 1);

    /* Response datagram: same constraints on the inbound path. */
    {
        uint8_t wrapped[128];
        int wrapped_len = socks5_udp_wrap(wrapped, (int)sizeof(wrapped),
                                          server1, 50000,
                                          (const uint8_t *)"EE", 2);
        addr_len = sizeof(relay_sock_addr);
        getsockname(relay_sock, (struct sockaddr *)&relay_sock_addr, &addr_len);
        sendto(fake_proxy, (const char *)wrapped, wrapped_len, 0,
               (struct sockaddr *)&relay_sock_addr, sizeof(relay_sock_addr));
    }
    g_test_winsock_ioctl_count = 0;
    g_test_windows_srw_exclusive_count = 0;
    udp_relay_test_handle_proxy_datagram(&relay, relay_sock, fake_proxy_addr,
                                         client_ip, 50000, 0,
                                         relay.sessions[0].generation,
                                         recv_buf);
    check_int("response datagram takes no exclusive lock",
              g_test_windows_srw_exclusive_count, 0);
    n = (int)recv(responder_receiver, (char *)wire, sizeof(wire), 0);
    check_int("response datagram still routes", n, 2);

    closesocket(fake_proxy);
    closesocket(relay_sock);
    closesocket(ctrl_sock);
    closesocket(responder_receiver);
    teardown_relay(&relay);
    conntrack_shutdown(&ct);
}

static void test_eviction_prefers_oldest_session(void) {
    conntrack_t ct;
    udp_relay_t relay;
    int evicted_index;

    g_test_windows_tick_ms = 10000;
    if (conntrack_init(&ct) != ERR_OK) {
        fprintf(stderr, "FAIL conntrack_init\n");
        failures++;
        return;
    }
    setup_relay(&relay, &ct);
    relay.session_capacity = 3;
    relay.local_sock = INVALID_SOCKET;

    for (int i = 0; i < 3; i++) {
        relay.sessions[i].active = 1;
        relay.sessions[i].client_ip = htonl(0x0A000002U);
        relay.sessions[i].client_port = (uint16_t)(50000 + i);
        relay.sessions[i].ctrl_sock = INVALID_SOCKET;
        relay.sessions[i].relay_sock = INVALID_SOCKET;
        relay.sessions[i].bucket = -1;
        relay.sessions[i].next_index = -1;
    }
    relay.sessions[0].last_activity = 5000;
    relay.sessions[1].last_activity = 1000;   /* oldest */
    relay.sessions[2].last_activity = 3000;
    relay.counters.active_sessions = 3;

    evicted_index = udp_relay_test_alloc_oldest(&relay);
    check_int("eviction picks the oldest session by timestamp",
              evicted_index, 1);
    check_int("eviction counter increments",
              (long)relay.counters.evicted_sessions, 1);

    teardown_relay(&relay);
    conntrack_shutdown(&ct);
}

static void test_periodic_cleanup_owns_idle_and_ctrl_liveness(void) {
    conntrack_t ct;
    udp_relay_t relay;
    SOCKET ctrl_sock;

    g_test_windows_tick_ms = 400000;
    if (conntrack_init(&ct) != ERR_OK) {
        fprintf(stderr, "FAIL conntrack_init\n");
        failures++;
        return;
    }
    setup_relay(&relay, &ct);
    relay.session_capacity = 3;
    relay.local_sock = INVALID_SOCKET;
    ctrl_sock = bind_loopback(htonl(0x7F000001U), 0, NULL);

    for (int i = 0; i < 3; i++) {
        relay.sessions[i].active = 1;
        relay.sessions[i].client_ip = htonl(0x0A000002U);
        relay.sessions[i].client_port = (uint16_t)(50000 + i);
        relay.sessions[i].ctrl_sock = INVALID_SOCKET;
        relay.sessions[i].relay_sock = INVALID_SOCKET;
        relay.sessions[i].bucket = -1;
        relay.sessions[i].next_index = -1;
    }
    relay.sessions[0].last_activity = 399000;   /* fresh, live ctrl */
    relay.sessions[0].ctrl_sock = ctrl_sock;
    relay.sessions[1].last_activity = 1000;     /* idle beyond 300s TTL */
    relay.sessions[2].last_activity = 399000;   /* fresh */
    relay.counters.active_sessions = 3;

    g_test_winsock_ioctl_count = 0;
    udp_relay_test_cleanup_idle(&relay);

    check_int("cleanup closes the idle-expired session",
              relay.sessions[1].active, 0);
    check_int("cleanup keeps fresh session with ctrl",
              relay.sessions[0].active, 1);
    check_int("cleanup keeps fresh session without ctrl",
              relay.sessions[2].active, 1);
    check_int("ctrl liveness probing moved to the periodic pass",
              g_test_winsock_ioctl_count >= 1, 1);

    closesocket(ctrl_sock);
    teardown_relay(&relay);
    conntrack_shutdown(&ct);
}

int main(void) {
    test_relay_wraps_each_datagram_to_its_framed_destination();
    test_relay_routes_response_by_unwrapped_source();
    test_datagram_path_avoids_probe_and_exclusive_locks();
    test_eviction_prefers_oldest_session();
    test_periodic_cleanup_owns_idle_and_ctrl_liveness();

    if (failures > 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    fprintf(stderr, "all tests passed\n");
    return 0;
}
