/*
 * Traffic classifier — determines the class of a packet.
 */
#ifndef WINTPROXY_PATH_CLASSIFY_H
#define WINTPROXY_PATH_CLASSIFY_H

#include "ndisapi/adapter.h"
#include "packet/context.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TRAFFIC_CLASS_INBOUND = 0,
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

/*
 * Direction is read from ctx->ndis_buf->m_dwDeviceFlags (PACKET_FLAG_ON_SEND/
 * PACKET_FLAG_ON_RECEIVE).
 */
traffic_class_t traffic_classify_packet(ndisapi_engine_t *engine,
                                        packet_ctx_t *ctx);
const char *adapter_name_for_handle(ndisapi_engine_t *engine, HANDLE h);
int path_is_private_ip(uint32_t ip);

#ifdef __cplusplus
}
#endif

#endif /* WINTPROXY_PATH_CLASSIFY_H */
