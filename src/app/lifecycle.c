#include "app/lifecycle.h"

void app_stop_services(app_lifecycle_services_t *services) {
    if (!services) return;

    if (services->tcp_ok && services->tcp_relay) {
        tcp_relay_stop(services->tcp_relay);
        services->tcp_ok = 0;
    }
    if (services->udp_ok && services->udp_relay) {
        udp_relay_stop(services->udp_relay);
        services->udp_ok = 0;
    }
    if (services->ndisapi_ok && services->ndisapi) {
        ndisapi_stop(services->ndisapi);
        services->ndisapi_ok = 0;
    }
    if (services->dns_ok && services->dns_hijack) {
        dns_hijack_shutdown(services->dns_hijack);
        services->dns_ok = 0;
    }
    if (services->proc_lookup_ok && services->proc_lookup) {
        proc_lookup_shutdown(services->proc_lookup);
        services->proc_lookup_ok = 0;
    }
    if (services->conntrack_ok && services->conntrack) {
        conntrack_shutdown(services->conntrack);
        services->conntrack_ok = 0;
    }
}
