#ifndef WINTPROXY_DIVERT_H
#define WINTPROXY_DIVERT_H

#include "config.h"
#include "connection.h"
#include "process.h"
#include "dns.h"
#include "constants.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#endif

#define DIVERT_WORKER_COUNT     WTP_DIVERT_WORKER_COUNT
#define DIVERT_MAX_PACKET_SIZE  WTP_DIVERT_MAX_PACKET_SIZE
#define DIVERT_QUEUE_LENGTH     WTP_DIVERT_QUEUE_LENGTH
#define DIVERT_QUEUE_TIME       WTP_DIVERT_QUEUE_TIME_MS
#define DIVERT_QUEUE_SIZE       WTP_DIVERT_QUEUE_SIZE

typedef struct {
    volatile LONG64 packets_recv;
    volatile LONG64 packets_sent;
    volatile LONG64 packets_dropped;
    volatile LONG64 send_failures;
    volatile LONG64 udp_forwarded;
} divert_counters_t;

typedef struct {
    HANDLE           handle;
    volatile int     running;
    HANDLE           workers[DIVERT_WORKER_COUNT];
    SOCKET           udp_fwd_sock;
    uint16_t         tcp_relay_port;
    uint16_t         udp_relay_port;
    uint32_t         loopback_if_idx;
    uint64_t         queue_length;
    uint64_t         queue_time;
    uint64_t         queue_size;
    divert_counters_t counters;
    conntrack_t     *conntrack;
    proc_lookup_t   *proc_lookup;
    dns_hijack_t    *dns_hijack;
    app_config_t    *config;
} divert_engine_t;

error_t divert_start(divert_engine_t *engine, app_config_t *config,
                     conntrack_t *conntrack, proc_lookup_t *proc_lookup,
                     dns_hijack_t *dns_hijack,
                     uint16_t tcp_relay_port, uint16_t udp_relay_port);
void    divert_stop(divert_engine_t *engine);
void    divert_snapshot_counters(divert_engine_t *engine, divert_counters_t *out);

#endif
