#ifndef WINTPROXY_APP_LIFECYCLE_H
#define WINTPROXY_APP_LIFECYCLE_H

#include "conntrack/conntrack.h"
#include "dns/hijack.h"
#include "ndisapi/adapter.h"
#include "process/lookup.h"
#include "relay/tcp.h"
#include "relay/udp.h"

typedef struct {
    int ndisapi_ok;
    ndisapi_engine_t *ndisapi;
    int tcp_ok;
    tcp_relay_t *tcp_relay;
    int udp_ok;
    udp_relay_t *udp_relay;
    int dns_ok;
    dns_hijack_t *dns_hijack;
    int proc_lookup_ok;
    proc_lookup_t *proc_lookup;
    int conntrack_ok;
    conntrack_t *conntrack;
} app_lifecycle_services_t;

void app_stop_services(app_lifecycle_services_t *services);

#endif
