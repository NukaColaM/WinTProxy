#ifndef WINTPROXY_DIVERT_H
#define WINTPROXY_DIVERT_H

#include "config.h"
#include "connection.h"
#include "process.h"
#include "dns.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#endif

#define DIVERT_WORKER_COUNT     4
#define DIVERT_MAX_PACKET_SIZE  65535
#define DIVERT_QUEUE_LENGTH     8192
#define DIVERT_QUEUE_TIME       2000

typedef struct {
    HANDLE           handle;
    volatile int     running;
    HANDLE           workers[DIVERT_WORKER_COUNT];
    SOCKET           udp_fwd_sock;
    conntrack_t     *conntrack;
    proc_lookup_t   *proc_lookup;
    dns_hijack_t    *dns_hijack;
    app_config_t    *config;
} divert_engine_t;

error_t divert_start(divert_engine_t *engine, app_config_t *config,
                     conntrack_t *conntrack, proc_lookup_t *proc_lookup,
                     dns_hijack_t *dns_hijack);
void    divert_stop(divert_engine_t *engine);

#endif
