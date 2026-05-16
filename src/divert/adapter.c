#include "divert/adapter.h"
#include "divert/io.h"
#include "flow/executor.h"
#include "flow/plan.h"
#include "packet/context.h"
#include "app/log.h"
#include "core/util.h"
#include <stdio.h>
#include <string.h>

#include "windivert/windivert.h"

#include <winsock2.h>
#include <iphlpapi.h>

void divert_counter_inc(volatile LONG64 *counter) {
    InterlockedIncrement64(counter);
}

int divert_send_packet(divert_engine_t *engine, const void *packet, UINT packet_len,
                       WINDIVERT_ADDRESS *addr, const char *context) {
    if (WinDivertSend(engine->handle, packet, packet_len, NULL, addr)) {
        divert_counter_inc(&engine->counters.packets_sent);
        return 1;
    }
    divert_counter_inc(&engine->counters.send_failures);
    LOG_WARN("WinDivertSend failed (%s): err=%lu", context ? context : "packet", GetLastError());
    return 0;
}

void divert_set_loopback_route(divert_engine_t *engine, WINDIVERT_ADDRESS *addr) {
    addr->Outbound = 1;
    addr->Loopback = 1;
    addr->Network.IfIdx = engine->loopback_if_idx;
    addr->Network.SubIfIdx = 0;
}

uint16_t divert_next_tcp_relay_src_port(divert_engine_t *engine) {
    LONG next = InterlockedIncrement(&engine->next_tcp_relay_src_port);
    LONG span = (LONG)WTP_TCP_RELAY_SRC_PORT_MAX - (LONG)WTP_TCP_RELAY_SRC_PORT_MIN + 1L;
    LONG offset;

    if (span <= 0) return WTP_TCP_RELAY_SRC_PORT_MIN;

    offset = (next - 1L) % span;
    if (offset < 0) offset += span;

    return (uint16_t)((LONG)WTP_TCP_RELAY_SRC_PORT_MIN + offset);
}

void divert_count_drop(divert_engine_t *engine) {
    divert_counter_inc(&engine->counters.packets_dropped);
}

void divert_count_udp_forwarded(divert_engine_t *engine) {
    divert_counter_inc(&engine->counters.udp_forwarded);
}

static uint32_t detect_loopback_if_idx(void) {
    DWORD if_idx = 0;
    DWORD ret = GetBestInterface(htonl(INADDR_LOOPBACK), &if_idx);
    if (ret == NO_ERROR && if_idx != 0) return if_idx;
    LOG_WARN("Could not detect loopback interface index (err=%lu); using IfIdx=1", ret);
    return 1;
}

static void tune_windivert_queue(divert_engine_t *engine) {
    WinDivertSetParam(engine->handle, WINDIVERT_PARAM_QUEUE_LENGTH, DIVERT_QUEUE_LENGTH);
    WinDivertSetParam(engine->handle, WINDIVERT_PARAM_QUEUE_TIME, DIVERT_QUEUE_TIME);
    WinDivertSetParam(engine->handle, WINDIVERT_PARAM_QUEUE_SIZE, DIVERT_QUEUE_SIZE);
    WinDivertGetParam(engine->handle, WINDIVERT_PARAM_QUEUE_LENGTH, &engine->queue_length);
    WinDivertGetParam(engine->handle, WINDIVERT_PARAM_QUEUE_TIME, &engine->queue_time);
    WinDivertGetParam(engine->handle, WINDIVERT_PARAM_QUEUE_SIZE, &engine->queue_size);
}

/* === Main worker loop: capture adapter only; flow planners produce actions. === */
static DWORD WINAPI divert_worker_proc(LPVOID param) {
    divert_engine_t *engine = (divert_engine_t *)param;
    uint8_t packet[DIVERT_MAX_PACKET_SIZE];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    while (engine->running) {
        if (!WinDivertRecv(engine->handle, packet, sizeof(packet), &packet_len, &addr)) {
            if (!engine->running) break;
            DWORD err = GetLastError();
            if (err == ERROR_NO_DATA || err == ERROR_INSUFFICIENT_BUFFER) continue;
            LOG_ERROR("WinDivertRecv failed: %lu", err);
            continue;
        }
        divert_counter_inc(&engine->counters.packets_recv);

        packet_ctx_t ctx;
        if (!packet_parse(&ctx, packet, packet_len)) {
            traffic_action_t pass;
            traffic_action_pass_raw(&pass, packet, packet_len, &addr, "unplanned pass");
            traffic_execute_action(engine, &pass);
            continue;
        }

        traffic_action_t action;
        traffic_plan_packet(engine, &ctx, &addr, &action);
        traffic_execute_action(engine, &action);
    }

    return 0;
}

static void divert_close_handle(divert_engine_t *engine) {
    if (engine->handle && engine->handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(engine->handle);
    }
    engine->handle = INVALID_HANDLE_VALUE;
}

static void divert_close_udp_socket(divert_engine_t *engine) {
    if (engine->udp_fwd_sock != INVALID_SOCKET) {
        closesocket(engine->udp_fwd_sock);
    }
    engine->udp_fwd_sock = INVALID_SOCKET;
}

static void divert_join_workers(divert_engine_t *engine) {
    for (int i = 0; i < DIVERT_WORKER_COUNT; i++) {
        if (engine->workers[i]) {
            WaitForSingleObject(engine->workers[i], 5000);
            CloseHandle(engine->workers[i]);
            engine->workers[i] = NULL;
        }
    }
}

static error_t divert_start_fail(divert_engine_t *engine, dns_hijack_t *dns_hijack,
                                 int dns_forwarder_started, error_t err) {
    engine->running = 0;
    if (dns_forwarder_started) {
        dns_hijack_shutdown(dns_hijack);
    }
    divert_close_handle(engine);
    divert_close_udp_socket(engine);
    divert_join_workers(engine);
    return err;
}

error_t divert_start(divert_engine_t *engine, app_config_t *config,
                    conntrack_t *conntrack, proc_lookup_t *proc_lookup,
                    dns_hijack_t *dns_hijack,
                    uint16_t tcp_relay_port, uint16_t udp_relay_port) {
    int dns_forwarder_started = 0;

    memset(engine, 0, sizeof(*engine));
    engine->handle = INVALID_HANDLE_VALUE;
    engine->config = config;
    engine->conntrack = conntrack;
    engine->proc_lookup = proc_lookup;
    engine->dns_hijack = dns_hijack;
    engine->tcp_relay_port = tcp_relay_port;
    engine->udp_relay_port = udp_relay_port;
    engine->loopback_if_idx = detect_loopback_if_idx();
    engine->running = 1;
    engine->udp_fwd_sock = INVALID_SOCKET;

    /*
     * WinDivert capture is intentionally broad enough to let flow/path planners
     * produce explicit direct/non-proxyable verdicts for private, multicast and
     * broadcast destinations instead of hiding those decisions in the filter.
     */
    char filter[1024];
    snprintf(filter, sizeof(filter),
        "((outbound and ip and !loopback and tcp) or "
        "(outbound and ip and !loopback and udp and "
        "udp.DstPort != 67 and udp.DstPort != 123 and "
        "udp.DstPort != 500 and udp.SrcPort != 500 and "
        "udp.DstPort != 4500 and udp.SrcPort != 4500)) "
        "or "
        "(outbound and ip and loopback and "
        "(tcp.SrcPort == %u or udp.SrcPort == %u))",
        engine->tcp_relay_port, engine->udp_relay_port);

    if (dns_hijack->enabled) {
        char dns_filter[512];
        uint8_t *ip_bytes = (uint8_t *)&dns_hijack->redirect_ip;

        if (dns_hijack->redirect_ip == LOOPBACK_ADDR) {
            /* Loopback DNS uses socket-based forwarding — no filter needed. */
            dns_filter[0] = '\0';
        } else {
            /* Non-loopback DNS server: capture inbound UDP/TCP responses by IP. */
            snprintf(dns_filter, sizeof(dns_filter),
                " or (inbound and ip and ((udp and ip.SrcAddr == %u.%u.%u.%u and udp.SrcPort == %u) or "
                "(tcp and ip.SrcAddr == %u.%u.%u.%u and tcp.SrcPort == %u)))",
                ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                dns_hijack->redirect_port,
                ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                dns_hijack->redirect_port);
        }
        strncat(filter, dns_filter, sizeof(filter) - strlen(filter) - 1);
    }

    LOG_TRACE("WinDivert filter: %s", filter);

    engine->handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (engine->handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        LOG_ERROR("WinDivertOpen failed: %lu", err);
        if (err == 5) LOG_ERROR("Access denied — run as Administrator");
        if (err == 577) LOG_ERROR("Driver not signed — install WinDivert driver");
        engine->running = 0;
        return ERR_PERMISSION;
    }

    tune_windivert_queue(engine);
    LOG_INFO("WinDivert queue: length=%llu time=%llums size=%llu bytes; loopback IfIdx=%lu",
             (unsigned long long)engine->queue_length,
             (unsigned long long)engine->queue_time,
             (unsigned long long)engine->queue_size,
             (unsigned long)engine->loopback_if_idx);

    engine->udp_fwd_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (engine->udp_fwd_sock == INVALID_SOCKET) {
        LOG_ERROR("UDP fwd socket: socket() failed: %d", WSAGetLastError());
        return divert_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_NETWORK);
    }
    {
        struct sockaddr_in bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind_addr.sin_port = 0;
        if (bind(engine->udp_fwd_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
            LOG_ERROR("UDP fwd socket: bind() failed: %d", WSAGetLastError());
            return divert_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_NETWORK);
        }
        struct sockaddr_in local;
        int local_len = sizeof(local);
        if (getsockname(engine->udp_fwd_sock, (struct sockaddr *)&local, &local_len) == SOCKET_ERROR) {
            LOG_ERROR("UDP fwd socket: getsockname() failed: %d", WSAGetLastError());
            return divert_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_NETWORK);
        }
        LOG_INFO("UDP forwarding socket bound to 127.0.0.1:%u", ntohs(local.sin_port));
    }

    if (dns_hijack->use_socket_fwd) {
        if (dns_hijack_start_forwarder(dns_hijack, engine->handle) != ERR_OK) {
            LOG_ERROR("Failed to start DNS forwarder");
            return divert_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_GENERIC);
        }
        dns_forwarder_started = 1;
    }

    for (int i = 0; i < DIVERT_WORKER_COUNT; i++) {
        engine->workers[i] = CreateThread(NULL, 0, divert_worker_proc, engine, 0, NULL);
        if (!engine->workers[i]) {
            LOG_ERROR("Failed to create WinDivert worker thread %d", i);
            return divert_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_GENERIC);
        }
    }

    LOG_INFO("WinDivert engine started with %d workers", DIVERT_WORKER_COUNT);
    return ERR_OK;
}

void divert_stop(divert_engine_t *engine) {
    engine->running = 0;
    if (engine->dns_hijack && engine->dns_hijack->use_socket_fwd) {
        dns_hijack_shutdown(engine->dns_hijack);
    }
    divert_close_handle(engine);
    divert_close_udp_socket(engine);
    divert_join_workers(engine);

    LOG_INFO("WinDivert engine stopped");
}

void divert_snapshot_counters(divert_engine_t *engine, divert_counters_t *out) {
    memset(out, 0, sizeof(*out));
    out->packets_recv = InterlockedExchange64(&engine->counters.packets_recv, 0);
    out->packets_sent = InterlockedExchange64(&engine->counters.packets_sent, 0);
    out->packets_dropped = InterlockedExchange64(&engine->counters.packets_dropped, 0);
    out->send_failures = InterlockedExchange64(&engine->counters.send_failures, 0);
    out->udp_forwarded = InterlockedExchange64(&engine->counters.udp_forwarded, 0);
}
