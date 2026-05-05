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
