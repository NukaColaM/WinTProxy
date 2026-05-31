/*
 * ndisapi packet engine implementation.
 *
 * Captures all Ethernet-level traffic from every network adapter using
 * ndisapi.dll's C API.  Each worker thread reads batches of packets,
 * parses them, and dispatches them via the flow planner/executor.
 *
 * In T1 (this task), all packets pass through unmodified (ON_SEND →
 * adapter, ON_RECEIVE → MSTCP).  Classification and proxy rewrite are
 * wired in T2–T5.
 */
#include "ndisapi/adapter.h"
#include "ndisapi/ndisapi.h"    /* vendored C API */
#include "flow/executor.h"
#include "flow/plan.h"
#include "packet/context.h"
#include "app/log.h"
#include "core/util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

void ndisapi_counter_inc(volatile LONG64 *counter) {
    InterlockedIncrement64(counter);
}

void ndisapi_count_drop(ndisapi_engine_t *engine) {
    ndisapi_counter_inc(&engine->counters.packets_dropped);
}

void ndisapi_count_udp_forwarded(ndisapi_engine_t *engine) {
    ndisapi_counter_inc(&engine->counters.udp_forwarded);
}

uint16_t ndisapi_next_tcp_relay_src_port(ndisapi_engine_t *engine) {
    LONG next = InterlockedIncrement(&engine->next_tcp_relay_src_port);
    LONG span = (LONG)WTP_TCP_RELAY_SRC_PORT_MAX - (LONG)WTP_TCP_RELAY_SRC_PORT_MIN + 1L;
    LONG offset;

    if (span <= 0) return WTP_TCP_RELAY_SRC_PORT_MIN;

    offset = (next - 1L) % span;
    if (offset < 0) offset += span;

    return (uint16_t)((LONG)WTP_TCP_RELAY_SRC_PORT_MIN + offset);
}

/* Single-packet send helpers.  The batch API is used in the worker loop;
 * these are convenience wrappers for the executor and DNS forwarder. */
int ndisapi_send_to_mstcp(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf) {
    DWORD sent = 0;
    if (SendPacketsToMstcpUnsorted(engine->driver_handle, &buf, 1, &sent)) {
        ndisapi_counter_inc(&engine->counters.packets_sent);
        return 1;
    }
    ndisapi_counter_inc(&engine->counters.send_failures);
    LOG_WARN("SendPacketsToMstcpUnsorted failed: err=%lu", GetLastError());
    return 0;
}

int ndisapi_send_to_adapter(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf) {
    DWORD sent = 0;
    if (SendPacketsToAdaptersUnsorted(engine->driver_handle, &buf, 1, &sent)) {
        ndisapi_counter_inc(&engine->counters.packets_sent);
        return 1;
    }
    ndisapi_counter_inc(&engine->counters.send_failures);
    LOG_WARN("SendPacketsToAdaptersUnsorted failed: err=%lu", GetLastError());
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Adapter enumeration                                               */
/* ------------------------------------------------------------------ */

static error_t ndisapi_enumerate_adapters(ndisapi_engine_t *engine) {
    TCP_AdapterList ad_list;

    memset(&ad_list, 0, sizeof(ad_list));

    if (!GetTcpipBoundAdaptersInfo(engine->driver_handle, &ad_list)) {
        LOG_ERROR("GetTcpipBoundAdaptersInfo failed: err=%lu", GetLastError());
        return ERR_NETWORK;
    }

    if (ad_list.m_nAdapterCount == 0) {
        LOG_ERROR("No network adapters found");
        return ERR_NOT_FOUND;
    }

    engine->adapter_count = ad_list.m_nAdapterCount;
    if (engine->adapter_count > NDISAPI_MAX_ADAPTERS) {
        LOG_WARN("Truncating adapter list from %lu to %d",
                 (unsigned long)engine->adapter_count, NDISAPI_MAX_ADAPTERS);
        engine->adapter_count = NDISAPI_MAX_ADAPTERS;
    }

    for (DWORD i = 0; i < engine->adapter_count; i++) {
        engine->adapter_handles[i] = ad_list.m_nAdapterHandle[i];
        memcpy(engine->adapter_mac[i], ad_list.m_czCurrentAddress[i], 6);

        /* Convert internal name to friendly name */
        ConvertWindows2000AdapterName(
            (LPCSTR)ad_list.m_szAdapterNameList[i],
            engine->adapter_names[i],
            sizeof(engine->adapter_names[i]));

        LOG_INFO("Adapter %lu: %s (MAC=%02X:%02X:%02X:%02X:%02X:%02X, MTU=%u)",
                 (unsigned long)i,
                 engine->adapter_names[i],
                 engine->adapter_mac[i][0], engine->adapter_mac[i][1],
                 engine->adapter_mac[i][2], engine->adapter_mac[i][3],
                 engine->adapter_mac[i][4], engine->adapter_mac[i][5],
                 ad_list.m_usMTU[i]);
    }

    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/*  Adapter mode / event setup                                        */
/* ------------------------------------------------------------------ */

static error_t ndisapi_setup_adapters(ndisapi_engine_t *engine) {
    for (DWORD i = 0; i < engine->adapter_count; i++) {
        ADAPTER_MODE mode;

        /* Set packet event so the driver signals us when packets arrive */
        if (!SetPacketEvent(engine->driver_handle,
                            engine->adapter_handles[i],
                            engine->packet_event)) {
            LOG_ERROR("SetPacketEvent failed for adapter %lu: err=%lu",
                      (unsigned long)i, GetLastError());
            return ERR_GENERIC;
        }

        /* Tunnel mode: intercept packets in both directions */
        memset(&mode, 0, sizeof(mode));
        mode.hAdapterHandle = engine->adapter_handles[i];
        mode.dwFlags = MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL;

        if (!SetAdapterMode(engine->driver_handle, &mode)) {
            LOG_ERROR("SetAdapterMode failed for adapter %lu: err=%lu",
                      (unsigned long)i, GetLastError());
            return ERR_GENERIC;
        }
    }

    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/*  Buffer pool allocation                                            */
/* ------------------------------------------------------------------ */

static int ndisapi_alloc_buffers(ndisapi_engine_t *engine) {
    DWORD total = (DWORD)NDISAPI_WORKER_COUNT * (DWORD)NDISAPI_BATCH_SIZE;
    DWORD i;

    /* Allocate the master pointer arrays */
    engine->worker_bufs = (PINTERMEDIATE_BUFFER *)
        calloc(total, sizeof(PINTERMEDIATE_BUFFER));
    engine->worker_read_ptrs = (PINTERMEDIATE_BUFFER *)
        calloc(total, sizeof(PINTERMEDIATE_BUFFER));
    engine->worker_to_adapter = (PINTERMEDIATE_BUFFER *)
        calloc(total, sizeof(PINTERMEDIATE_BUFFER));
    engine->worker_to_mstcp = (PINTERMEDIATE_BUFFER *)
        calloc(total, sizeof(PINTERMEDIATE_BUFFER));

    if (!engine->worker_bufs || !engine->worker_read_ptrs ||
        !engine->worker_to_adapter || !engine->worker_to_mstcp) {
        LOG_ERROR("Failed to allocate ndisapi buffer pointer arrays");
        return 0;
    }

    /* Allocate each INTERMEDIATE_BUFFER */
    for (i = 0; i < total; i++) {
        engine->worker_bufs[i] = (PINTERMEDIATE_BUFFER)
            calloc(1, sizeof(INTERMEDIATE_BUFFER));
        if (!engine->worker_bufs[i]) {
            LOG_ERROR("Failed to allocate INTERMEDIATE_BUFFER %lu", (unsigned long)i);
            return 0;
        }
        engine->worker_read_ptrs[i] = engine->worker_bufs[i];
    }

    LOG_INFO("Allocated %lu INTERMEDIATE_BUFFER (%lu KB)",
             (unsigned long)total,
             (unsigned long)(total * sizeof(INTERMEDIATE_BUFFER) / 1024));
    return 1;
}

static void ndisapi_free_buffers(ndisapi_engine_t *engine) {
    DWORD total = (DWORD)NDISAPI_WORKER_COUNT * (DWORD)NDISAPI_BATCH_SIZE;
    DWORD i;

    if (engine->worker_bufs) {
        for (i = 0; i < total; i++) {
            free(engine->worker_bufs[i]);
        }
        free(engine->worker_bufs);
        engine->worker_bufs = NULL;
    }
    free(engine->worker_read_ptrs);
    engine->worker_read_ptrs = NULL;
    free(engine->worker_to_adapter);
    engine->worker_to_adapter = NULL;
    free(engine->worker_to_mstcp);
    engine->worker_to_mstcp = NULL;
}

/* ------------------------------------------------------------------ */
/*  Worker thread                                                     */
/* ------------------------------------------------------------------ */

/*
 * Pass-through worker (T1).
 * Reads a batch, parses each packet, separates by direction, sends back.
 *
 * worker_idx is encoded in the thread parameter:
 *   worker_base = worker_idx * NDISAPI_BATCH_SIZE
 */
static DWORD WINAPI ndisapi_worker_proc(LPVOID param) {
    ndisapi_engine_t *engine = (ndisapi_engine_t *)param;

    /* Each worker owns a slice of the shared buffer pool.
     * Worker index assigned atomically at thread start.
     * worker 0: indices [0 .. BATCH-1]
     * worker 1: [BATCH .. 2*BATCH-1], etc. */
    static volatile LONG g_worker_idx = 0;
    LONG my_idx = InterlockedIncrement(&g_worker_idx) - 1;
    DWORD batch  = (DWORD)NDISAPI_BATCH_SIZE;
    DWORD offset = (DWORD)my_idx * batch;

    PINTERMEDIATE_BUFFER *read_ptrs  = engine->worker_read_ptrs + offset;
    PINTERMEDIATE_BUFFER *to_adapter = engine->worker_to_adapter + offset;
    PINTERMEDIATE_BUFFER *to_mstcp   = engine->worker_to_mstcp + offset;
    DWORD to_adapter_count, to_mstcp_count;
    DWORD packets_read, packets_sent, j;

    while (engine->running) {
        /* Wait for packets */
        WaitForSingleObject(engine->packet_event, 100);
        ResetEvent(engine->packet_event);

        if (!engine->running) break;

        /* Read a batch */
        if (!ReadPacketsUnsorted(engine->driver_handle, read_ptrs, batch, &packets_read)) {
            if (!engine->running) break;
            continue;
        }

        if (packets_read == 0) continue;

        {
            LONG64 inc = (LONG64)packets_read;
            InterlockedAdd64(&engine->counters.packets_recv, inc);
        }

        /* Separate by direction */
        to_adapter_count = 0;
        to_mstcp_count   = 0;

        for (j = 0; j < packets_read; j++) {
            PINTERMEDIATE_BUFFER buf = read_ptrs[j];
            if (!buf || buf->m_Length < ETHER_HDR_LEN) continue;

            packet_ctx_t ctx;
            if (packet_parse(&ctx, buf)) {
                traffic_action_t action;
                traffic_plan_packet(engine, &ctx, &action);

                /* Batch by action type */
                switch (action.type) {
                case TRAFFIC_ACTION_REWRITE_SEND:
                    packet_recalculate_checksums(action.ctx);
                    /* fallthrough */
                case TRAFFIC_ACTION_PASS:
                    if (action.ndis_buf->m_dwDeviceFlags & PACKET_FLAG_ON_SEND)
                        to_adapter[to_adapter_count++] = action.ndis_buf;
                    else
                        to_mstcp[to_mstcp_count++] = action.ndis_buf;
                    break;
                case TRAFFIC_ACTION_DROP:
                    ndisapi_count_drop(engine);
                    break;
                default:
                    /* FORWARD actions: execute inline (UDP relay, DNS forward) */
                    traffic_execute_action(engine, &action);
                    break;
                }
            } else {
                /* Unparseable packet — pass through */
                if (buf->m_dwDeviceFlags & PACKET_FLAG_ON_SEND) {
                    to_adapter[to_adapter_count++] = buf;
                } else {
                    to_mstcp[to_mstcp_count++] = buf;
                }
            }
        }

        /* Send to adapter (outbound packets) */
        if (to_adapter_count > 0) {
            if (SendPacketsToAdaptersUnsorted(engine->driver_handle,
                                               to_adapter, to_adapter_count,
                                               &packets_sent)) {
                InterlockedAdd64(&engine->counters.packets_sent,
                                 (LONG64)packets_sent);
            } else {
                LOG_WARN("SendPacketsToAdaptersUnsorted failed: err=%lu",
                         GetLastError());
                ndisapi_counter_inc(&engine->counters.send_failures);
            }
        }

        /* Send to MSTCP (inbound / reverted packets) */
        if (to_mstcp_count > 0) {
            packets_sent = 0;
            LOG_TRACE("Sending %lu packets to MSTCP", (unsigned long)to_mstcp_count);
            if (SendPacketsToMstcpUnsorted(engine->driver_handle,
                                            to_mstcp, to_mstcp_count,
                                            &packets_sent)) {
                InterlockedAdd64(&engine->counters.packets_sent,
                                 (LONG64)packets_sent);
            } else {
                LOG_WARN("SendPacketsToMstcpUnsorted failed: err=%lu",
                         GetLastError());
                ndisapi_counter_inc(&engine->counters.send_failures);
            }
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Engine lifecycle                                                  */
/* ------------------------------------------------------------------ */

static void ndisapi_close_driver(ndisapi_engine_t *engine) {
    if (engine->driver_handle && engine->driver_handle != INVALID_HANDLE_VALUE) {
        /* Remove packet events and reset modes on all adapters */
        if (engine->adapter_count > 0) {
            for (DWORD i = 0; i < engine->adapter_count; i++) {
                ADAPTER_MODE mode;
                memset(&mode, 0, sizeof(mode));
                mode.hAdapterHandle = engine->adapter_handles[i];
                mode.dwFlags = 0;
                SetAdapterMode(engine->driver_handle, &mode);
                SetPacketEvent(engine->driver_handle,
                               engine->adapter_handles[i], NULL);
            }
        }

        CloseFilterDriver(engine->driver_handle);
    }
    engine->driver_handle = INVALID_HANDLE_VALUE;

    if (engine->packet_event) {
        CloseHandle(engine->packet_event);
        engine->packet_event = NULL;
    }
}

static void ndisapi_close_udp_socket(ndisapi_engine_t *engine) {
    if (engine->udp_fwd_sock != INVALID_SOCKET) {
        closesocket(engine->udp_fwd_sock);
    }
    engine->udp_fwd_sock = INVALID_SOCKET;
}

static void ndisapi_join_workers(ndisapi_engine_t *engine) {
    for (int i = 0; i < NDISAPI_WORKER_COUNT; i++) {
        if (engine->workers[i]) {
            WaitForSingleObject(engine->workers[i], 5000);
            CloseHandle(engine->workers[i]);
            engine->workers[i] = NULL;
        }
    }
}

static error_t ndisapi_start_fail(ndisapi_engine_t *engine,
                                  dns_hijack_t *dns_hijack,
                                  int dns_forwarder_started,
                                  error_t err) {
    engine->running = 0;
    if (dns_forwarder_started) {
        dns_hijack_shutdown(dns_hijack);
    }
    ndisapi_close_driver(engine);
    ndisapi_close_udp_socket(engine);
    ndisapi_join_workers(engine);
    return err;
}

error_t ndisapi_start(ndisapi_engine_t *engine, app_config_t *config,
                      conntrack_t *conntrack, proc_lookup_t *proc_lookup,
                      dns_hijack_t *dns_hijack,
                      uint16_t tcp_relay_port, uint16_t udp_relay_port) {
    int dns_forwarder_started = 0;
    error_t err;

    memset(engine, 0, sizeof(*engine));
    engine->driver_handle = INVALID_HANDLE_VALUE;
    engine->config = config;
    engine->conntrack = conntrack;
    engine->proc_lookup = proc_lookup;
    engine->dns_hijack = dns_hijack;
    engine->tcp_relay_port = tcp_relay_port;
    engine->udp_relay_port = udp_relay_port;
    engine->running = 1;
    engine->udp_fwd_sock = INVALID_SOCKET;

    /* 1. Open the driver.  OpenFilterDriver returns a CNdisApi* cast to HANDLE;
     * it never returns NULL (new always succeeds).  Check IsDriverLoaded(). */
    engine->driver_handle = OpenFilterDriver(L"NDISRD");
    if (!engine->driver_handle) {
        LOG_ERROR("OpenFilterDriver returned NULL");
        engine->running = 0;
        return ERR_PERMISSION;
    }
    if (!IsDriverLoaded(engine->driver_handle)) {
        DWORD err_code = GetLastError();
        LOG_ERROR("WinpkFilter driver not loaded: err=%lu", err_code);
        if (err_code == 2) {
            LOG_ERROR("ndisrd.sys driver not found — install WinpkFilter driver");
        } else if (err_code == 5) {
            LOG_ERROR("Access denied — is the WinpkFilter driver installed?");
        }
        engine->running = 0;
        return ERR_PERMISSION;
    }

    {
        DWORD ver = GetDriverVersion(engine->driver_handle);
        LOG_INFO("WinpkFilter driver version %lu.%lu.%lu",
                 (unsigned long)((ver >> 24) & 0xFF),
                 (unsigned long)((ver >> 16) & 0xFF),
                 (unsigned long)(ver & 0xFFFF));
    }

    /* 2. Enumerate adapters */
    err = ndisapi_enumerate_adapters(engine);
    if (err != ERR_OK) {
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, err);
    }

    /* 3. Set pool size (in number of packets) */
    {
        DWORD pool_size = (DWORD)NDISAPI_WORKER_COUNT * (DWORD)NDISAPI_BATCH_SIZE * 2;
        SetPoolSize(pool_size);
        LOG_INFO("ndisapi buffer pool size set to %lu", (unsigned long)pool_size);
    }

    /* 4. Create shared packet event */
    engine->packet_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!engine->packet_event) {
        LOG_ERROR("CreateEvent for packet_event failed: %lu", GetLastError());
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_GENERIC);
    }

    /* 5. Set adapter modes and events */
    err = ndisapi_setup_adapters(engine);
    if (err != ERR_OK) {
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, err);
    }

    /* 6. Allocate INTERMEDIATE_BUFFER pool */
    if (!ndisapi_alloc_buffers(engine)) {
        LOG_ERROR("Failed to allocate ndisapi buffer pool");
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_MEMORY);
    }

    /* 7. Create UDP forwarding socket (for UDP relay) */
    engine->udp_fwd_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (engine->udp_fwd_sock == INVALID_SOCKET) {
        LOG_ERROR("UDP fwd socket: socket() failed: %d", WSAGetLastError());
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_NETWORK);
    }
    {
        struct sockaddr_in bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind_addr.sin_port = 0;
        if (bind(engine->udp_fwd_sock, (struct sockaddr *)&bind_addr,
                 sizeof(bind_addr)) == SOCKET_ERROR) {
            LOG_ERROR("UDP fwd socket: bind() failed: %d", WSAGetLastError());
            return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_NETWORK);
        }
        struct sockaddr_in local;
        int local_len = sizeof(local);
        if (getsockname(engine->udp_fwd_sock, (struct sockaddr *)&local,
                        &local_len) == SOCKET_ERROR) {
            LOG_ERROR("UDP fwd socket: getsockname() failed: %d", WSAGetLastError());
            return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_NETWORK);
        }
        LOG_INFO("UDP forwarding socket bound to 127.0.0.1:%u", ntohs(local.sin_port));
    }

    /* 8. Start DNS forwarder if loopback DNS is configured */
    if (dns_hijack->use_socket_fwd) {
        if (dns_hijack_start_forwarder(dns_hijack, engine) != ERR_OK) {
            LOG_ERROR("Failed to start DNS forwarder");
            return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_GENERIC);
        }
        dns_forwarder_started = 1;
    }

    /* 9. Spawn worker threads */
    for (int i = 0; i < NDISAPI_WORKER_COUNT; i++) {
        engine->workers[i] = CreateThread(NULL, 0, ndisapi_worker_proc,
                                          engine, 0, NULL);
        if (!engine->workers[i]) {
            LOG_ERROR("Failed to create ndisapi worker thread %d", i);
            return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_GENERIC);
        }
    }

    LOG_INFO("ndisapi engine started with %d workers across %lu adapters",
             NDISAPI_WORKER_COUNT, (unsigned long)engine->adapter_count);
    return ERR_OK;
}

void ndisapi_stop(ndisapi_engine_t *engine) {
    engine->running = 0;

    /* Signal the packet event so blocked workers wake up */
    if (engine->packet_event) {
        SetEvent(engine->packet_event);
    }

    /* Shutdown DNS forwarder */
    if (engine->dns_hijack && engine->dns_hijack->use_socket_fwd) {
        dns_hijack_shutdown(engine->dns_hijack);
    }

    /* Join workers */
    ndisapi_join_workers(engine);

    /* Free buffers */
    ndisapi_free_buffers(engine);

    /* Close driver (resets adapter modes) */
    ndisapi_close_driver(engine);

    /* Close UDP socket */
    ndisapi_close_udp_socket(engine);

    LOG_INFO("ndisapi engine stopped");
}

void ndisapi_snapshot_counters(ndisapi_engine_t *engine, ndisapi_counters_t *out) {
    memset(out, 0, sizeof(*out));
    out->packets_recv   = InterlockedExchange64(&engine->counters.packets_recv, 0);
    out->packets_sent   = InterlockedExchange64(&engine->counters.packets_sent, 0);
    out->packets_dropped= InterlockedExchange64(&engine->counters.packets_dropped, 0);
    out->send_failures  = InterlockedExchange64(&engine->counters.send_failures, 0);
    out->udp_forwarded  = InterlockedExchange64(&engine->counters.udp_forwarded, 0);
}
