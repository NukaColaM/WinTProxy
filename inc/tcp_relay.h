#ifndef WINTPROXY_TCP_RELAY_H
#define WINTPROXY_TCP_RELAY_H

#include "connection.h"
#include "config.h"
#include "common.h"
#include "constants.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#endif

#define TCP_RELAY_PORT  WTP_TCP_RELAY_PORT
#define TCP_RELAY_WORKER_MAX WTP_TCP_RELAY_WORKER_MAX
#define TCP_RELAY_CONN_MAX WTP_TCP_RELAY_CONN_MAX

typedef struct tcp_conn_s tcp_conn_t;

typedef struct {
    volatile LONG64 active_connections;
    volatile LONG64 accepted_connections;
    volatile LONG64 rejected_connections;
    volatile LONG64 connect_failures;
    volatile LONG64 handshake_failures;
    volatile LONG64 bytes_up;
    volatile LONG64 bytes_down;
} tcp_relay_counters_t;

typedef struct {
    SOCKET           listen_sock;
    uint16_t         port;
    volatile int     running;
    HANDLE           thread;
    HANDLE           iocp;
    HANDLE           workers[TCP_RELAY_WORKER_MAX];
    int              worker_count;
    tcp_conn_t      *connections;
    tcp_conn_t      *free_list;
    tcp_conn_t      *active_list;
    size_t           connection_capacity;
    SRWLOCK          conn_lock;
    conntrack_t     *conntrack;
    proxy_config_t  *proxy;
    tcp_relay_counters_t counters;
} tcp_relay_t;

error_t tcp_relay_start(tcp_relay_t *relay, conntrack_t *conntrack, proxy_config_t *proxy);
void    tcp_relay_stop(tcp_relay_t *relay);
void    tcp_relay_snapshot_counters(tcp_relay_t *relay, tcp_relay_counters_t *out);

#endif
