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

typedef struct {
    SOCKET           listen_sock;
    volatile int     running;
    HANDLE           thread;
    conntrack_t     *conntrack;
    proxy_config_t  *proxy;
} tcp_relay_t;

error_t tcp_relay_start(tcp_relay_t *relay, conntrack_t *conntrack, proxy_config_t *proxy);
void    tcp_relay_stop(tcp_relay_t *relay);

#endif
