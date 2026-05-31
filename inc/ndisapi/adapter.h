/*
 * ndisapi packet engine — replaces divert/adapter.h.
 * Uses ndisapi.dll C API to intercept Ethernet-level traffic from all adapters.
 */
#ifndef WINTPROXY_NDISAPI_ADAPTER_H
#define WINTPROXY_NDISAPI_ADAPTER_H

#include "app/config.h"
#include "conntrack/conntrack.h"
#include "process/lookup.h"
#include "dns/hijack.h"
#include "core/constants.h"
#include "ndisapi/ndisapi.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#endif

/* === Tunables === */
/* With the unsorted API, ReadPacketsUnsorted delivers ALL pending packets to
 * each caller.  Multiple workers racing on the same event would each receive
 * full copies, causing packet duplication.  Use a single worker until a
 * per-worker event/queue model is added. */
#define NDISAPI_WORKER_COUNT     1
#define NDISAPI_BATCH_SIZE       256
#define NDISAPI_MAX_ADAPTERS     32

/* === Counters (same structure, renamed) === */
typedef struct {
    volatile LONG64 packets_recv;
    volatile LONG64 packets_sent;
    volatile LONG64 packets_dropped;
    volatile LONG64 send_failures;
    volatile LONG64 udp_forwarded;
} ndisapi_counters_t;

/* === Engine state === */
typedef struct ndisapi_engine_s {
    /* ndisapi driver */
    HANDLE            driver_handle;          /* from OpenFilterDriver */
    HANDLE            packet_event;           /* shared event for all adapters */

    /* Adapters */
    DWORD             adapter_count;
    HANDLE            adapter_handles[NDISAPI_MAX_ADAPTERS];
    char              adapter_names[NDISAPI_MAX_ADAPTERS][256];
    uint8_t           adapter_mac[NDISAPI_MAX_ADAPTERS][6];

    /* Worker threads */
    volatile int      running;
    HANDLE            workers[NDISAPI_WORKER_COUNT];

    /* Per-worker batch buffers (INTERMEDIATE_BUFFER pool) */
    PINTERMEDIATE_BUFFER *worker_bufs;        /* array of NDISAPI_WORKER_COUNT * NDISAPI_BATCH_SIZE ptrs */
    PINTERMEDIATE_BUFFER *worker_read_ptrs;   /* pointer arrays for ReadPacketsUnsorted */
    PINTERMEDIATE_BUFFER *worker_to_adapter;  /* temp: packets to send to adapter */
    PINTERMEDIATE_BUFFER *worker_to_mstcp;    /* temp: packets to send to MSTCP */

    /* UDP forwarding to relay */
    SOCKET            udp_fwd_sock;
    uint16_t          tcp_relay_port;
    uint16_t          udp_relay_port;

    /* TCP relay source port allocator */
    volatile LONG     next_tcp_relay_src_port;

    /* Counters */
    ndisapi_counters_t counters;

    /* Subsystem pointers (set by main) */
    conntrack_t      *conntrack;
    proc_lookup_t    *proc_lookup;
    dns_hijack_t     *dns_hijack;
    app_config_t     *config;
} ndisapi_engine_t;

/* === Lifecycle === */
error_t ndisapi_start(ndisapi_engine_t *engine, app_config_t *config,
                      conntrack_t *conntrack, proc_lookup_t *proc_lookup,
                      dns_hijack_t *dns_hijack,
                      uint16_t tcp_relay_port, uint16_t udp_relay_port);
void    ndisapi_stop(ndisapi_engine_t *engine);
void    ndisapi_snapshot_counters(ndisapi_engine_t *engine, ndisapi_counters_t *out);

/* === I/O helpers (replaces divert/io.h) === */
void     ndisapi_counter_inc(volatile LONG64 *counter);
uint16_t ndisapi_next_tcp_relay_src_port(ndisapi_engine_t *engine);
void     ndisapi_count_drop(ndisapi_engine_t *engine);
void     ndisapi_count_udp_forwarded(ndisapi_engine_t *engine);

/* === Packet send — used by executor and DNS forwarder === */
int      ndisapi_send_to_mstcp(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf);
int      ndisapi_send_to_adapter(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf);

#endif /* WINTPROXY_NDISAPI_ADAPTER_H */
