#ifndef WINTPROXY_RELAY_UDP_H
#define WINTPROXY_RELAY_UDP_H

#include "conntrack/conntrack.h"
#include "app/config.h"
#include "core/common.h"
#include "core/constants.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#endif

#define UDP_RELAY_PORT      WTP_UDP_RELAY_PORT
#define UDP_SESSION_MAX     WTP_UDP_SESSION_MAX
#define UDP_SESSION_BUCKETS WTP_UDP_SESSION_BUCKETS
#define UDP_SESSION_TTL_SEC WTP_UDP_SESSION_TTL_SEC
#define UDP_RETRY_DELAY_MS  WTP_UDP_RETRY_DELAY_MS

typedef struct {
    int              active;
    uint32_t         generation;
    uint32_t         client_ip;
    uint16_t         client_port;
    SOCKET           ctrl_sock;
    SOCKET           relay_sock;
    struct sockaddr_in relay_addr;
    uint64_t         last_activity;
    uint64_t         last_retry;
    int              active_prev;
    int              active_next;
    int              next_index;
    int              bucket;
} udp_session_t;

typedef struct {
    volatile LONG64 active_sessions;
    volatile LONG64 created_sessions;
    volatile LONG64 evicted_sessions;
    volatile LONG64 dropped_datagrams;
    volatile LONG64 bytes_up;
    volatile LONG64 bytes_down;
} udp_relay_counters_t;

typedef struct {
    SOCKET           local_sock;
    uint16_t         port;
    volatile int     running;
    HANDLE           thread;
    conntrack_t     *conntrack;
    proxy_config_t  *proxy;
    udp_session_t   *sessions;
    int             *session_buckets;
    size_t           session_capacity;
    size_t           bucket_count;
    int              active_head;
    int              active_tail;
    SRWLOCK          session_lock;
    udp_relay_counters_t counters;
} udp_relay_t;

error_t udp_relay_start(udp_relay_t *relay, conntrack_t *conntrack, proxy_config_t *proxy);
void    udp_relay_stop(udp_relay_t *relay);
void    udp_relay_snapshot_counters(udp_relay_t *relay, udp_relay_counters_t *out);

#endif
