#include <stdio.h>
#include <string.h>

#include "app/lifecycle.h"

enum {
    EVENT_TCP_STOP = 1,
    EVENT_UDP_STOP,
    EVENT_NDISAPI_STOP,
    EVENT_DNS_STOP,
    EVENT_PROC_STOP,
    EVENT_CONNTRACK_STOP
};

static int failures = 0;
static int events[16];
static int event_count = 0;

static void record_event(int event) {
    if (event_count < (int)(sizeof(events) / sizeof(events[0]))) {
        events[event_count++] = event;
    }
}

static int event_index(int event) {
    for (int i = 0; i < event_count; i++) {
        if (events[i] == event) return i;
    }
    return -1;
}

static void check_before(const char *name, int earlier, int later) {
    int earlier_idx = event_index(earlier);
    int later_idx = event_index(later);
    if (earlier_idx < 0 || later_idx < 0 || earlier_idx >= later_idx) {
        fprintf(stderr, "FAIL %s: order violation\n", name);
        failures++;
    }
}

void tcp_relay_stop(tcp_relay_t *relay) {
    (void)relay;
    record_event(EVENT_TCP_STOP);
}

void udp_relay_stop(udp_relay_t *relay) {
    (void)relay;
    record_event(EVENT_UDP_STOP);
}

void ndisapi_stop(ndisapi_engine_t *engine) {
    (void)engine;
    record_event(EVENT_NDISAPI_STOP);
}

void dns_hijack_shutdown(dns_hijack_t *dh) {
    (void)dh;
    record_event(EVENT_DNS_STOP);
}

void proc_lookup_shutdown(proc_lookup_t *pl) {
    (void)pl;
    record_event(EVENT_PROC_STOP);
}

void conntrack_shutdown(conntrack_t *ct) {
    (void)ct;
    record_event(EVENT_CONNTRACK_STOP);
}

static void test_relays_stop_before_packet_engine(void) {
    app_lifecycle_services_t services;
    ndisapi_engine_t ndisapi;
    tcp_relay_t tcp_relay;
    udp_relay_t udp_relay;
    dns_hijack_t dns_hijack;
    proc_lookup_t proc_lookup;
    conntrack_t conntrack;

    memset(&services, 0, sizeof(services));
    memset(&ndisapi, 0, sizeof(ndisapi));
    memset(&tcp_relay, 0, sizeof(tcp_relay));
    memset(&udp_relay, 0, sizeof(udp_relay));
    memset(&dns_hijack, 0, sizeof(dns_hijack));
    memset(&proc_lookup, 0, sizeof(proc_lookup));
    memset(&conntrack, 0, sizeof(conntrack));

    services.ndisapi_ok = 1;
    services.ndisapi = &ndisapi;
    services.tcp_ok = 1;
    services.tcp_relay = &tcp_relay;
    services.udp_ok = 1;
    services.udp_relay = &udp_relay;
    services.dns_ok = 1;
    services.dns_hijack = &dns_hijack;
    services.proc_lookup_ok = 1;
    services.proc_lookup = &proc_lookup;
    services.conntrack_ok = 1;
    services.conntrack = &conntrack;

    event_count = 0;
    app_stop_services(&services);

    check_before("tcp relay before ndisapi", EVENT_TCP_STOP, EVENT_NDISAPI_STOP);
    check_before("udp relay before ndisapi", EVENT_UDP_STOP, EVENT_NDISAPI_STOP);
    check_before("ndisapi before dns", EVENT_NDISAPI_STOP, EVENT_DNS_STOP);
    check_before("dns before process lookup", EVENT_DNS_STOP, EVENT_PROC_STOP);
    check_before("process lookup before conntrack", EVENT_PROC_STOP, EVENT_CONNTRACK_STOP);
}

int main(void) {
    test_relays_stop_before_packet_engine();

    if (failures > 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    fprintf(stderr, "all tests passed\n");
    return 0;
}
