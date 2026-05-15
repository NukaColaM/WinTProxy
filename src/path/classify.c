#include "path/classify.h"
#include "dns/hijack.h"
#include "core/util.h"

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

traffic_class_t traffic_classify_packet(divert_engine_t *engine,
                                        packet_ctx_t *ctx,
                                        WINDIVERT_ADDRESS *addr) {
    if (ctx->tcp_hdr && engine->dns_hijack->enabled &&
        ctx->src_ip == engine->dns_hijack->redirect_ip &&
        ctx->src_port == engine->dns_hijack->redirect_port &&
        ((!addr->Outbound) || (addr->Outbound && addr->Loopback && ctx->dst_ip != LOOPBACK_ADDR)))
        return TRAFFIC_CLASS_TCP_DNS_RETURN;

    if (ctx->udp_hdr && addr->Outbound && addr->Loopback &&
        engine->dns_hijack->enabled &&
        ctx->src_ip == engine->dns_hijack->redirect_ip &&
        ctx->src_port == engine->dns_hijack->redirect_port)
        return TRAFFIC_CLASS_DNS_RESPONSE_LOOPBACK;

    if (!addr->Outbound) {
        if (ctx->udp_hdr && !addr->Loopback &&
            engine->dns_hijack->enabled &&
            ctx->src_ip == engine->dns_hijack->redirect_ip &&
            ctx->src_port == engine->dns_hijack->redirect_port)
            return TRAFFIC_CLASS_DNS_RESPONSE;
        return TRAFFIC_CLASS_INBOUND;
    }

    if (ctx->tcp_hdr && ctx->src_port == engine->tcp_relay_port) return TRAFFIC_CLASS_TCP_RETURN;
    if (ctx->udp_hdr && ctx->src_port == engine->udp_relay_port) return TRAFFIC_CLASS_UDP_RETURN;

    if (ctx->dst_ip == engine->config->proxy.ip_addr &&
        ctx->dst_port == engine->config->proxy.port)
        return TRAFFIC_CLASS_SELF_PROXY;

    if (ctx->dst_port == engine->tcp_relay_port || ctx->dst_port == engine->udp_relay_port)
        return TRAFFIC_CLASS_SELF_RELAY;

    if (engine->dns_hijack->enabled &&
        ctx->dst_ip == engine->dns_hijack->redirect_ip &&
        ctx->dst_port == engine->dns_hijack->redirect_port)
        return TRAFFIC_CLASS_SELF_DNS;

    if (ctx->udp_hdr && dns_hijack_is_dns_request(ctx->dst_port) && engine->dns_hijack->enabled)
        return TRAFFIC_CLASS_DNS_QUERY_UDP;

    if (ctx->tcp_hdr && dns_hijack_is_dns_request(ctx->dst_port) && engine->dns_hijack->enabled)
        return TRAFFIC_CLASS_DNS_QUERY_TCP;

    if (engine->config->bypass.broadcast && ctx->dst_ip == 0xFFFFFFFF) return TRAFFIC_CLASS_NON_PROXYABLE;
    if (engine->config->bypass.multicast && is_multicast_ip(ctx->dst_ip)) return TRAFFIC_CLASS_NON_PROXYABLE;

    if (engine->config->bypass.private_ips && path_is_private_ip(ctx->dst_ip))
        return TRAFFIC_CLASS_NON_PROXYABLE;

    return TRAFFIC_CLASS_POLICY;
}

const char *traffic_class_name(traffic_class_t cls) {
    switch (cls) {
    case TRAFFIC_CLASS_INBOUND: return "inbound";
    case TRAFFIC_CLASS_DNS_RESPONSE_LOOPBACK: return "dns-response-loopback";
    case TRAFFIC_CLASS_DNS_RESPONSE: return "dns-response";
    case TRAFFIC_CLASS_TCP_DNS_RETURN: return "tcp-dns-return";
    case TRAFFIC_CLASS_TCP_RETURN: return "tcp-return";
    case TRAFFIC_CLASS_UDP_RETURN: return "udp-return";
    case TRAFFIC_CLASS_SELF_PROXY: return "self-proxy";
    case TRAFFIC_CLASS_SELF_RELAY: return "self-relay";
    case TRAFFIC_CLASS_SELF_DNS: return "self-dns";
    case TRAFFIC_CLASS_DNS_QUERY_UDP: return "dns-query-udp";
    case TRAFFIC_CLASS_DNS_QUERY_TCP: return "dns-query-tcp";
    case TRAFFIC_CLASS_NON_PROXYABLE: return "non-proxyable";
    case TRAFFIC_CLASS_POLICY: return "policy";
    }
    return "unknown";
}
