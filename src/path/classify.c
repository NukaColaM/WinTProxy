/*
 * Traffic classifier — ndisapi direction model.
 * Determines the traffic class of a packet based on direction, ports, and IPs.
 */
#include "path/classify.h"
#include "dns/hijack.h"
#include "core/util.h"
#include "app/log.h"

const char *adapter_name_for_handle(ndisapi_engine_t *engine, HANDLE h) {
    for (DWORD i = 0; i < engine->adapter_count; i++) {
        if (engine->adapter_handles[i] == h) {
            return engine->adapter_names[i];
        }
    }
    return "?";
}

int path_is_private_ip(uint32_t ip) {
    unsigned char *b = (unsigned char *)&ip;
    if (b[0] == 10) return 1;
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return 1;
    if (b[0] == 192 && b[1] == 168) return 1;
    if (b[0] == 169 && b[1] == 254) return 1;
    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return 1;
    return 0;
}

static int is_multicast_ip(uint32_t ip) {
    unsigned char *octets = (unsigned char *)&ip;
    return octets[0] >= 224 && octets[0] <= 239;
}

traffic_class_t traffic_classify_packet(ndisapi_engine_t *engine,
                                        packet_ctx_t *ctx) {
    int outbound;

    if (!ctx || !ctx->ndis_buf) return TRAFFIC_CLASS_INBOUND;

    outbound = (ctx->ndis_buf->m_dwDeviceFlags & PACKET_FLAG_ON_SEND) != 0;

    /* === TCP DNS return: inbound from redirect DNS over TCP === */
    if (ctx->tcp_hdr && engine->dns_hijack->enabled &&
        !outbound &&
        ctx->src_ip == engine->dns_hijack->redirect_ip &&
        ctx->src_port == engine->dns_hijack->redirect_port)
        return TRAFFIC_CLASS_TCP_DNS_RETURN;

    /* === Inbound (non-DNS) or DNS response === */
    if (!outbound) {
        if (ctx->udp_hdr && engine->dns_hijack->enabled &&
            ctx->src_ip == engine->dns_hijack->redirect_ip &&
            ctx->src_port == engine->dns_hijack->redirect_port)
            return TRAFFIC_CLASS_DNS_RESPONSE;
        return TRAFFIC_CLASS_INBOUND;
    }

    /* === Outbound: return paths === */
    if (ctx->tcp_hdr && ctx->src_port == engine->tcp_relay_port)
        return TRAFFIC_CLASS_TCP_RETURN;
    if (ctx->udp_hdr && ctx->src_port == engine->udp_relay_port)
        return TRAFFIC_CLASS_UDP_RETURN;

    /* === Self/loop protection === */
    if (ctx->dst_ip == engine->config->proxy.ip_addr &&
        ctx->dst_port == engine->config->proxy.port)
        return TRAFFIC_CLASS_SELF_PROXY;

    if (ctx->dst_port == engine->tcp_relay_port ||
        ctx->dst_port == engine->udp_relay_port)
        return TRAFFIC_CLASS_SELF_RELAY;

    if (engine->dns_hijack->enabled &&
        ctx->dst_ip == engine->dns_hijack->redirect_ip &&
        ctx->dst_port == engine->dns_hijack->redirect_port)
        return TRAFFIC_CLASS_SELF_DNS;

    /* Outbound DNS response from the redirect server (e.g. mihomo
     * sending its reply back to the forwarder socket on loopback).
     * Without this, the response would be classified as POLICY and
     * proxied through SOCKS5, destroying the DNS reply. */
    if (outbound && ctx->udp_hdr && engine->dns_hijack->enabled &&
        ctx->src_ip == engine->dns_hijack->redirect_ip &&
        ctx->src_port == engine->dns_hijack->redirect_port)
        return TRAFFIC_CLASS_SELF_DNS;

    /* === DNS queries === */
    if (ctx->udp_hdr && dns_hijack_is_dns_request(ctx->dst_port) &&
        engine->dns_hijack->enabled)
        return TRAFFIC_CLASS_DNS_QUERY_UDP;

    if (ctx->tcp_hdr && dns_hijack_is_dns_request(ctx->dst_port) &&
        engine->dns_hijack->enabled)
        return TRAFFIC_CLASS_DNS_QUERY_TCP;

    /* === Non-proxyable destinations === */
    if (engine->config->bypass.broadcast && ctx->dst_ip == 0xFFFFFFFF)
        return TRAFFIC_CLASS_NON_PROXYABLE;

    if (engine->config->bypass.multicast && is_multicast_ip(ctx->dst_ip))
        return TRAFFIC_CLASS_NON_PROXYABLE;

    if (engine->config->bypass.private_ips && path_is_private_ip(ctx->dst_ip))
        return TRAFFIC_CLASS_NON_PROXYABLE;

    /* === Default: policy-based routing === */
    return TRAFFIC_CLASS_POLICY;
}
