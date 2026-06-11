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
#include "flow/action.h"
#include "core/constants.h"
#include "ndisapi/ndisapi.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#endif

/* === Tunables === */
#define NDISAPI_BATCH_SIZE       256
#define NDISAPI_MAX_ADAPTERS     32
#define NDISAPI_PACKET_POOL_WAIT_MS 2
#define NDISAPI_FLOW_WORKER_MIN  2
#define NDISAPI_FLOW_WORKER_MAX  16
#define NDISAPI_FLOW_QUEUE_DEPTH 512
#define NDISAPI_FLOW_ENQUEUE_WAIT_MS 2
#define NDISAPI_SENDER_QUEUE_DEPTH 1024
#define NDISAPI_SENDER_COUNT 2

/* === Counters (same structure, renamed) === */
typedef struct {
    volatile LONG64 packets_recv;
    volatile LONG64 packets_sent;
    volatile LONG64 packets_dropped;
    volatile LONG64 send_failures;
    volatile LONG64 udp_forwarded;
    volatile LONG64 pool_exhausted;
    volatile LONG64 adapter_queue_flushes;
    volatile LONG64 overload_drops;
    volatile LONG64 enqueue_timeouts;
    volatile LONG64 adapter_restart_required;
} ndisapi_counters_t;

typedef struct ndisapi_engine_s ndisapi_engine_t;
typedef struct ndisapi_packet_pool_s ndisapi_packet_pool_t;
typedef struct ndisapi_packet_block_s ndisapi_packet_block_t;
typedef struct ndisapi_flow_worker_s ndisapi_flow_worker_t;
typedef struct ndisapi_sender_s ndisapi_sender_t;

typedef enum {
    NDISAPI_SEND_TARGET_MSTCP = 0,
    NDISAPI_SEND_TARGET_ADAPTER = 1
} ndisapi_send_target_t;

typedef struct {
    PINTERMEDIATE_BUFFER buf;
    ndisapi_packet_block_t *block;
    int free_after_send;
} ndisapi_send_item_t;

struct ndisapi_packet_block_s {
    ndisapi_packet_pool_t *pool;
    ndisapi_packet_block_t *next;
    volatile LONG ref_count;
    HANDLE adapter_handle;
    DWORD adapter_index;
    DWORD direction;
    INTERMEDIATE_BUFFER buffer;
    packet_ctx_t context;
    traffic_action_t action;
};

struct ndisapi_packet_pool_s {
    SRWLOCK lock;
    ndisapi_packet_block_t *blocks;
    ndisapi_packet_block_t *free_list;
    DWORD capacity;
    DWORD free_count;
};

struct ndisapi_flow_worker_s {
    ndisapi_engine_t *engine;
    DWORD worker_index;
    HANDLE thread;
    HANDLE work_event;
    SRWLOCK lock;
    ndisapi_packet_block_t *queue[NDISAPI_FLOW_QUEUE_DEPTH];
    DWORD head;
    DWORD tail;
    DWORD count;
};

struct ndisapi_sender_s {
    ndisapi_engine_t *engine;
    ndisapi_send_target_t target;
    HANDLE thread;
    HANDLE work_event;
    SRWLOCK lock;
    ndisapi_send_item_t queue[NDISAPI_SENDER_QUEUE_DEPTH];
    DWORD head;
    DWORD tail;
    DWORD count;
};

typedef struct {
    ndisapi_engine_t    *engine;
    DWORD                adapter_index;
    HANDLE               adapter_handle;
    HANDLE               packet_event;
    HANDLE               thread;
    PETH_M_REQUEST       read_request;
} ndisapi_adapter_reader_t;

/* === Engine state === */
struct ndisapi_engine_s {
    /* ndisapi driver */
    HANDLE            driver_handle;          /* from OpenFilterDriver */

    /* Adapters */
    DWORD             adapter_count;
    HANDLE            adapter_handles[NDISAPI_MAX_ADAPTERS];
    char              adapter_names[NDISAPI_MAX_ADAPTERS][256];
    uint8_t           adapter_mac[NDISAPI_MAX_ADAPTERS][6];

    /* Worker threads */
    volatile int      running;
    ndisapi_adapter_reader_t readers[NDISAPI_MAX_ADAPTERS];
    DWORD             flow_worker_count;
    ndisapi_flow_worker_t flow_workers[NDISAPI_FLOW_WORKER_MAX];
    ndisapi_sender_t  senders[NDISAPI_SENDER_COUNT];
    HANDLE            adapter_change_event;
    HANDLE            adapter_monitor_thread;
    volatile int      adapter_restart_required;

    /* UDP forwarding to relay */
    SOCKET            udp_fwd_sock;
    uint16_t          tcp_relay_port;
    uint16_t          udp_relay_port;

    /* TCP relay source port allocator */
    volatile LONG     next_tcp_relay_src_port;

    /* Counters */
    ndisapi_counters_t counters;

    /* Caller-owned packet storage shared by readers/workers/senders */
    ndisapi_packet_pool_t packet_pool;

    /* Subsystem pointers (set by main) */
    conntrack_t      *conntrack;
    proc_lookup_t    *proc_lookup;
    dns_hijack_t     *dns_hijack;
    app_config_t     *config;
};

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

/* === Packet block pool === */
int      ndisapi_packet_pool_init(ndisapi_packet_pool_t *pool, DWORD capacity);
void     ndisapi_packet_pool_destroy(ndisapi_packet_pool_t *pool);
ndisapi_packet_block_t *ndisapi_packet_block_acquire(ndisapi_packet_pool_t *pool,
                                                     HANDLE adapter_handle,
                                                     DWORD adapter_index);
ndisapi_packet_block_t *ndisapi_packet_block_acquire_or_flush(ndisapi_engine_t *engine,
                                                             HANDLE adapter_handle,
                                                             DWORD adapter_index,
                                                             DWORD wait_ms);
void     ndisapi_packet_block_retain(ndisapi_packet_block_t *block);
void     ndisapi_packet_block_release(ndisapi_packet_block_t *block);

/* === Flow worker dispatch === */
DWORD    ndisapi_flow_worker_count_for_cpu(DWORD cpu_count);
uint64_t ndisapi_packet_flow_hash(PINTERMEDIATE_BUFFER buf);
DWORD    ndisapi_packet_worker_index(ndisapi_engine_t *engine,
                                     PINTERMEDIATE_BUFFER buf);
int      ndisapi_flow_worker_enqueue(ndisapi_engine_t *engine,
                                     ndisapi_packet_block_t *block,
                                     DWORD wait_ms);

/* === Dedicated sender dispatch === */
int      ndisapi_enqueue_send_batch_to_mstcp(ndisapi_engine_t *engine,
                                             ndisapi_send_item_t *items,
                                             DWORD count);
int      ndisapi_enqueue_send_batch_to_adapter(ndisapi_engine_t *engine,
                                               ndisapi_send_item_t *items,
                                               DWORD count);

/* === Packet send — executor-owned send boundary === */
int      ndisapi_send_batch_to_mstcp(ndisapi_engine_t *engine,
                                     PINTERMEDIATE_BUFFER *bufs,
                                     DWORD count);
int      ndisapi_send_batch_to_adapter(ndisapi_engine_t *engine,
                                       PINTERMEDIATE_BUFFER *bufs,
                                       DWORD count);
int      ndisapi_send_to_mstcp(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf);
int      ndisapi_send_to_adapter(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf);

#endif /* WINTPROXY_NDISAPI_ADAPTER_H */
