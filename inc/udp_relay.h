#ifndef WINTPROXY_UDP_RELAY_H
#define WINTPROXY_UDP_RELAY_H

#include "connection.h"
#include "config.h"
#include "common.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#endif

#define UDP_RELAY_PORT      34011
#define UDP_SESSION_MAX     256
#define UDP_SESSION_TTL_SEC 300
#define UDP_RETRY_DELAY_MS  5000

typedef struct {
    int              active;
    uint16_t         client_port;
    SOCKET           ctrl_sock;
    SOCKET           relay_sock;
    struct sockaddr_in relay_addr;
    uint64_t         last_activity;
    uint64_t         last_retry;
} udp_session_t;

typedef struct {
    SOCKET           local_sock;
    volatile int     running;
    HANDLE           thread;
    conntrack_t     *conntrack;
    proxy_config_t  *proxy;
    udp_session_t    sessions[UDP_SESSION_MAX];
    SRWLOCK          session_lock;
} udp_relay_t;

error_t udp_relay_start(udp_relay_t *relay, conntrack_t *conntrack, proxy_config_t *proxy);
void    udp_relay_stop(udp_relay_t *relay);

#endif
