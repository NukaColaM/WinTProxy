#include "flow/executor.h"
#include "divert/io.h"
#include "dns/hijack.h"
#include "app/log.h"
#include "core/constants.h"
#include <string.h>

void traffic_execute_action(divert_engine_t *engine, traffic_action_t *action) {
    if (!engine || !action) return;

    switch (action->type) {
    case TRAFFIC_ACTION_PASS:
        if (action->packet && action->packet_len > 0 && action->addr) {
            divert_send_packet(engine, action->packet, action->packet_len,
                               action->addr, action->context ? action->context : "pass");
        }
        break;

    case TRAFFIC_ACTION_REWRITE_SEND:
        if (action->ctx && action->addr) {
            packet_recalculate_checksums(action->ctx, action->addr);
            divert_send_packet(engine, action->ctx->packet, action->ctx->packet_len,
                               action->addr, action->context ? action->context : "rewrite/send");
        }
        break;

    case TRAFFIC_ACTION_DROP:
        divert_count_drop(engine);
        break;

    case TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY: {
        const uint8_t *udp_data = NULL;
        UINT udp_data_len = 0;
        packet_ctx_t *ctx = action->ctx;
        if (!ctx || !packet_payload(ctx, &udp_data, &udp_data_len) || !udp_data || udp_data_len == 0) {
            LOG_WARN("UDP PROXY: failed to extract payload");
            break;
        }

        if (udp_data_len > WTP_UDP_BUFFER_SIZE) {
            LOG_WARN("UDP PROXY: payload too large: %u", udp_data_len);
            break;
        }

        uint8_t framed[6 + WTP_UDP_BUFFER_SIZE];
        int framed_len = (int)(6U + udp_data_len);
        memcpy(framed, &ctx->src_ip, 4);
        framed[4] = (uint8_t)(ctx->src_port >> 8);
        framed[5] = (uint8_t)(ctx->src_port & 0xFF);
        memcpy(framed + 6, udp_data, udp_data_len);

        struct sockaddr_in relay_dest;
        memset(&relay_dest, 0, sizeof(relay_dest));
        relay_dest.sin_family = AF_INET;
        relay_dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        relay_dest.sin_port = htons(engine->udp_relay_port);

        int fwd = sendto(engine->udp_fwd_sock, (const char *)framed, framed_len, 0,
                         (struct sockaddr *)&relay_dest, sizeof(relay_dest));
        if (fwd == SOCKET_ERROR) {
            LOG_WARN("UDP fwd sendto failed: %d", WSAGetLastError());
        } else {
            divert_count_udp_forwarded(engine);
            LOG_PACKET("UDP fwd: sent %u bytes (port %u) to relay", udp_data_len, ctx->src_port);
        }
        break;
    }

    case TRAFFIC_ACTION_FORWARD_DNS_TO_RESOLVER: {
        const uint8_t *dns_data = NULL;
        UINT dns_data_len = 0;
        packet_ctx_t *ctx = action->ctx;
        if (!ctx || !packet_payload(ctx, &dns_data, &dns_data_len) || !dns_data || dns_data_len < 2) {
            LOG_WARN("DNS hijack: malformed DNS payload for forward action");
            break;
        }

        error_t err = dns_hijack_forward_query(engine->dns_hijack,
            dns_data, (int)dns_data_len,
            action->dns_forward.src_port,
            action->dns_forward.original_dns_ip,
            action->dns_forward.original_dns_port,
            action->dns_forward.client_ip,
            action->dns_forward.if_idx,
            action->dns_forward.sub_if_idx);
        if (err != ERR_OK) {
            LOG_WARN("DNS hijack: loopback forward failed (%d), passing original query", err);
            divert_send_packet(engine, ctx->packet, ctx->packet_len, action->addr, "DNS forward fallback");
        }
        break;
    }
    }
}
