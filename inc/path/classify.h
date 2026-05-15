#ifndef WINTPROXY_PATH_CLASSIFY_H
#define WINTPROXY_PATH_CLASSIFY_H

#include "divert/adapter.h"
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TRAFFIC_CLASS_INBOUND = 0,
    TRAFFIC_CLASS_DNS_RESPONSE_LOOPBACK,
    TRAFFIC_CLASS_DNS_RESPONSE,
    TRAFFIC_CLASS_TCP_DNS_RETURN,
    TRAFFIC_CLASS_TCP_RETURN,
    TRAFFIC_CLASS_UDP_RETURN,
    TRAFFIC_CLASS_SELF_PROXY,
    TRAFFIC_CLASS_SELF_RELAY,
    TRAFFIC_CLASS_SELF_DNS,
    TRAFFIC_CLASS_DNS_QUERY_UDP,
    TRAFFIC_CLASS_DNS_QUERY_TCP,
    TRAFFIC_CLASS_NON_PROXYABLE,
    TRAFFIC_CLASS_POLICY
} traffic_class_t;

traffic_class_t traffic_classify_packet(divert_engine_t *engine,
                                        packet_ctx_t *ctx,
                                        WINDIVERT_ADDRESS *addr);
const char *traffic_class_name(traffic_class_t cls);
int path_is_private_ip(uint32_t ip);

#ifdef __cplusplus
}
#endif

#endif
