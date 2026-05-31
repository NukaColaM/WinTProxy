/*
 * Flow executor — dispatches traffic actions to ndisapi send primitives.
 * Replaces divert/io.h calls with ndisapi C API equivalents.
 */
#include "flow/executor.h"
#include "dns/hijack.h"
#include "app/log.h"
#include "core/constants.h"
#include <string.h>

/*
 * Determine the correct ndisapi send direction for a given buffer.
 * - PACKET_FLAG_ON_SEND + no rewrite: send to adapter (outbound)
 * - PACKET_FLAG_ON_RECEIVE + no rewrite: send to MSTCP (inbound)
 * - Rewrite actions may override (handled in T3+).
 *
 * For T1 pass-through, we use the flag directly.
 */
static int send_buf(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf) {
    if (!buf) return 0;

    if (buf->m_dwDeviceFlags & PACKET_FLAG_ON_SEND) {
        return ndisapi_send_to_adapter(engine, buf);
    } else {
        return ndisapi_send_to_mstcp(engine, buf);
    }
}

void traffic_execute_action(ndisapi_engine_t *engine, traffic_action_t *action) {
    if (!engine || !action) return;

    switch (action->type) {
    case TRAFFIC_ACTION_PASS:
        if (action->ndis_buf) {
            send_buf(engine, action->ndis_buf);
        }
        break;

    case TRAFFIC_ACTION_REWRITE_SEND:
        if (action->ctx && action->ndis_buf) {
            packet_recalculate_checksums(action->ctx);
            send_buf(engine, action->ndis_buf);
        }
        break;

    case TRAFFIC_ACTION_DROP:
        ndisapi_count_drop(engine);
        break;

    case TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY: {
        const uint8_t *udp_data = NULL;
        UINT udp_data_len = 0;
        packet_ctx_t *ctx = action->ctx;
        if (!ctx || !packet_payload(ctx, &udp_data, &udp_data_len) ||
            !udp_data || udp_data_len == 0) {
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

        int fwd = sendto(engine->udp_fwd_sock, (const char *)framed,
                         framed_len, 0,
                         (struct sockaddr *)&relay_dest, sizeof(relay_dest));
        if (fwd == SOCKET_ERROR) {
            LOG_WARN("UDP fwd sendto failed: %d", WSAGetLastError());
        } else {
            ndisapi_count_udp_forwarded(engine);
            LOG_TRACE("UDP fwd: sent %u bytes (port %u) to relay",
                      udp_data_len, ctx->src_port);
        }
        break;
    }

    case TRAFFIC_ACTION_FORWARD_DNS_TO_RESOLVER: {
        const uint8_t *dns_data = NULL;
        UINT dns_data_len = 0;
        packet_ctx_t *ctx = action->ctx;
        if (!ctx || !packet_payload(ctx, &dns_data, &dns_data_len) ||
            !dns_data || dns_data_len < 2) {
            LOG_WARN("DNS hijack: malformed DNS payload for forward action");
            break;
        }

        error_t err = dns_hijack_forward_query(engine->dns_hijack,
            dns_data, (int)dns_data_len,
            action->dns_forward.src_port,
            action->dns_forward.original_dns_ip,
            action->dns_forward.original_dns_port,
            action->dns_forward.client_ip,
            action->dns_forward.adapter_handle);
        if (err != ERR_OK) {
            LOG_WARN("DNS hijack: loopback forward failed (%d), "
                     "passing original query", err);
            /* Fallback: pass the original packet through */
            if (action->ndis_buf) {
                send_buf(engine, action->ndis_buf);
            }
        }
        break;
    }
    }
}
