/*
 * Flow executor — dispatches traffic actions to ndisapi send primitives.
 * Replaces divert/io.h calls with ndisapi C API equivalents.
 */
#include "flow/executor.h"
#include "dns/hijack.h"
#include "app/log.h"
#include "core/constants.h"
#include <stdlib.h>
#include <string.h>

static traffic_send_target_t resolve_send_target(PINTERMEDIATE_BUFFER buf,
                                                 traffic_send_target_t target) {
    if (target == TRAFFIC_SEND_TO_ADAPTER) {
        return TRAFFIC_SEND_TO_ADAPTER;
    }
    if (target == TRAFFIC_SEND_TO_MSTCP) {
        return TRAFFIC_SEND_TO_MSTCP;
    }

    if (buf && (buf->m_dwDeviceFlags & PACKET_FLAG_ON_SEND)) {
        return TRAFFIC_SEND_TO_ADAPTER;
    }
    return TRAFFIC_SEND_TO_MSTCP;
}

static void flush_driver_sends(ndisapi_engine_t *engine,
                               traffic_send_target_t target,
                               ndisapi_send_item_t *items,
                               size_t *count) {
    if (!engine || !items || !count || *count == 0) return;

    if (target == TRAFFIC_SEND_TO_ADAPTER) {
        ndisapi_enqueue_send_batch_to_adapter(engine, items, (DWORD)*count);
    } else if (target == TRAFFIC_SEND_TO_MSTCP) {
        ndisapi_enqueue_send_batch_to_mstcp(engine, items, (DWORD)*count);
    }
    *count = 0;
}

static void queue_driver_send(ndisapi_engine_t *engine,
                              traffic_action_t *action,
                              traffic_send_target_t target,
                              ndisapi_send_item_t *to_adapter,
                              size_t *adapter_count,
                              ndisapi_send_item_t *to_mstcp,
                              size_t *mstcp_count) {
    traffic_send_target_t resolved;
    PINTERMEDIATE_BUFFER buf = action ? action->ndis_buf : NULL;
    ndisapi_send_item_t item;

    if (!buf) return;

    memset(&item, 0, sizeof(item));
    item.buf = buf;
    item.block = action ? action->owner_block : NULL;

    resolved = resolve_send_target(buf, target);
    if (resolved == TRAFFIC_SEND_TO_ADAPTER) {
        to_adapter[(*adapter_count)++] = item;
        if (*adapter_count == NDISAPI_BATCH_SIZE) {
            flush_driver_sends(engine, TRAFFIC_SEND_TO_ADAPTER,
                               to_adapter, adapter_count);
        }
    } else {
        to_mstcp[(*mstcp_count)++] = item;
        if (*mstcp_count == NDISAPI_BATCH_SIZE) {
            flush_driver_sends(engine, TRAFFIC_SEND_TO_MSTCP,
                               to_mstcp, mstcp_count);
        }
    }
}

static void apply_packet_rewrite(packet_ctx_t *ctx,
                                 const traffic_packet_rewrite_t *rewrite) {
    if (!ctx || !rewrite) return;

    if ((rewrite->flags & TRAFFIC_PACKET_REWRITE_IP_SRC) && ctx->ip_hdr) {
        ctx->ip_hdr->ip_src = rewrite->ip_src;
    }
    if ((rewrite->flags & TRAFFIC_PACKET_REWRITE_IP_DST) && ctx->ip_hdr) {
        ctx->ip_hdr->ip_dst = rewrite->ip_dst;
    }
    if ((rewrite->flags & TRAFFIC_PACKET_REWRITE_TCP_SPORT) && ctx->tcp_hdr) {
        ctx->tcp_hdr->th_sport = htons(rewrite->tcp_sport);
    }
    if ((rewrite->flags & TRAFFIC_PACKET_REWRITE_TCP_DPORT) && ctx->tcp_hdr) {
        ctx->tcp_hdr->th_dport = htons(rewrite->tcp_dport);
    }
    if ((rewrite->flags & TRAFFIC_PACKET_REWRITE_UDP_SPORT) && ctx->udp_hdr) {
        ctx->udp_hdr->uh_sport = htons(rewrite->udp_sport);
    }
    if ((rewrite->flags & TRAFFIC_PACKET_REWRITE_UDP_DPORT) && ctx->udp_hdr) {
        ctx->udp_hdr->uh_dport = htons(rewrite->udp_dport);
    }
    if (rewrite->flags & TRAFFIC_PACKET_REWRITE_SWAP_ETH) {
        swap_ether_addrs(ctx->eth_hdr);
    }
    if ((rewrite->flags & TRAFFIC_PACKET_REWRITE_CLAMP_TCP_MSS) && ctx->tcp_hdr) {
        packet_clamp_tcp_mss(ctx, rewrite->tcp_mss);
    }
}

static void execute_udp_forward(ndisapi_engine_t *engine,
                                traffic_action_t *action) {
    const uint8_t *udp_data = NULL;
    UINT udp_data_len = 0;
    packet_ctx_t *ctx = action ? action->ctx : NULL;

    if (!ctx || !packet_payload(ctx, &udp_data, &udp_data_len) ||
        !udp_data || udp_data_len == 0) {
        LOG_WARN("UDP PROXY: failed to extract payload");
        return;
    }

    if (udp_data_len > WTP_UDP_BUFFER_SIZE) {
        LOG_WARN("UDP PROXY: payload too large: %u", udp_data_len);
        return;
    }

    /* Frame: src_ip(4) src_port(2) dst_ip(4) dst_port(2) payload. The
     * explicit destination lets the relay wrap each datagram toward the
     * destination it was actually sent to. */
    uint8_t framed[12 + WTP_UDP_BUFFER_SIZE];
    int framed_len = (int)(12U + udp_data_len);
    memcpy(framed, &ctx->src_ip, 4);
    framed[4] = (uint8_t)(ctx->src_port >> 8);
    framed[5] = (uint8_t)(ctx->src_port & 0xFF);
    memcpy(framed + 6, &ctx->dst_ip, 4);
    framed[10] = (uint8_t)(ctx->dst_port >> 8);
    framed[11] = (uint8_t)(ctx->dst_port & 0xFF);
    memcpy(framed + 12, udp_data, udp_data_len);

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
}

static error_t execute_dns_forward(ndisapi_engine_t *engine,
                                   traffic_action_t *action) {
    const uint8_t *dns_data = NULL;
    UINT dns_data_len = 0;
    packet_ctx_t *ctx = action ? action->ctx : NULL;

    if (!ctx || !packet_payload(ctx, &dns_data, &dns_data_len) ||
        !dns_data || dns_data_len < 2) {
        LOG_WARN("DNS hijack: malformed DNS payload for forward action");
        return ERR_PARAM;
    }

    return dns_hijack_forward_query(engine->dns_hijack,
        dns_data, (int)dns_data_len,
        action->dns_forward.src_port,
        action->dns_forward.original_dns_ip,
        action->dns_forward.original_dns_port,
        action->dns_forward.client_ip,
        action->dns_forward.adapter_handle);
}

static void fill_adapter_ethernet(ndisapi_engine_t *engine,
                                  HANDLE adapter_handle,
                                  ether_header_ptr eth) {
    if (!engine || !eth) return;

    memset(eth->h_dest, 0, 6);
    memset(eth->h_source, 0, 6);
    if (adapter_handle && engine->adapter_count > 0) {
        for (DWORD i = 0; i < engine->adapter_count; i++) {
            if (engine->adapter_handles[i] == adapter_handle) {
                memcpy(eth->h_dest, engine->adapter_mac[i], 6);
                memcpy(eth->h_source, engine->adapter_mac[i], 6);
                return;
            }
        }
    }
    if (engine->adapter_count > 0) {
        memcpy(eth->h_dest, engine->adapter_mac[0], 6);
        memcpy(eth->h_source, engine->adapter_mac[0], 6);
    }
}

static void execute_dns_response_injection(ndisapi_engine_t *engine,
                                           traffic_action_t *action) {
    const traffic_dns_response_t *response;
    PINTERMEDIATE_BUFFER pkt;
    ether_header_ptr eth;
    iphdr_ptr ip;
    udphdr_ptr udp;
    uint8_t *dns_payload;
    int ip_len;
    int total_len;

    if (!engine || !action) return;
    response = &action->dns_response;
    if (!response->dns_payload || response->dns_len < 2 ||
        response->dns_len > WTP_DNS_FORWARD_BUFFER_SIZE) {
        LOG_WARN("DNS fwd: malformed synthetic response");
        ndisapi_count_drop(engine);
        return;
    }

    pkt = (PINTERMEDIATE_BUFFER)calloc(1, sizeof(INTERMEDIATE_BUFFER));
    if (!pkt) {
        LOG_WARN("DNS fwd: response packet allocation failed");
        ndisapi_count_drop(engine);
        return;
    }

    eth = (ether_header_ptr)pkt->m_IBuffer;
    ip  = (iphdr_ptr)(pkt->m_IBuffer + ETHER_HDR_LEN);
    udp = (udphdr_ptr)(pkt->m_IBuffer + ETHER_HDR_LEN + 20);
    dns_payload = pkt->m_IBuffer + ETHER_HDR_LEN + 20 + 8;

    ip_len = 20 + 8 + response->dns_len;
    total_len = ETHER_HDR_LEN + ip_len;

    fill_adapter_ethernet(engine, response->adapter_handle, eth);
    eth->h_proto = htons(ETH_P_IP);

    memset(ip, 0, 20);
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_len = htons((uint16_t)ip_len);
    ip->ip_ttl = 64;
    ip->ip_p = WTP_IPPROTO_UDP;
    ip->ip_src = response->original_dns_ip;
    ip->ip_dst = response->client_ip;

    udp->uh_sport = htons(response->original_dns_port);
    udp->uh_dport = htons(response->client_port);
    udp->uh_ulen = htons((uint16_t)(8 + response->dns_len));
    udp->uh_sum = 0;

    memcpy(dns_payload, response->dns_payload, (size_t)response->dns_len);
    dns_payload[0] = (uint8_t)(response->dns_txid >> 8);
    dns_payload[1] = (uint8_t)(response->dns_txid & 0xFF);

    pkt->m_Length = (DWORD)total_len;
    pkt->m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    pkt->m_hAdapter = response->adapter_handle;
    if (!pkt->m_hAdapter && engine->adapter_count > 0) {
        pkt->m_hAdapter = engine->adapter_handles[0];
    }

    RecalculateUDPChecksum(pkt);
    RecalculateIPChecksum(pkt);

    {
        ndisapi_send_item_t item;
        memset(&item, 0, sizeof(item));
        item.buf = pkt;
        item.free_after_send = 1;
        ndisapi_enqueue_send_batch_to_mstcp(engine, &item, 1);
    }
}

static void execute_one_action(ndisapi_engine_t *engine,
                               traffic_action_t *action,
                               ndisapi_send_item_t *to_adapter,
                               size_t *adapter_count,
                               ndisapi_send_item_t *to_mstcp,
                               size_t *mstcp_count) {
    if (!action) return;

    switch (action->type) {
    case TRAFFIC_ACTION_PASS:
        queue_driver_send(engine, action, action->send_target,
                          to_adapter, adapter_count, to_mstcp, mstcp_count);
        break;

    case TRAFFIC_ACTION_REWRITE_SEND:
        if (action->ctx && action->ndis_buf) {
            apply_packet_rewrite(action->ctx, &action->rewrite);
            packet_recalculate_checksums(action->ctx);
            queue_driver_send(engine, action, action->send_target,
                              to_adapter, adapter_count,
                              to_mstcp, mstcp_count);
        }
        break;

    case TRAFFIC_ACTION_DROP:
        ndisapi_count_drop(engine);
        break;

    case TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY:
        execute_udp_forward(engine, action);
        break;

    case TRAFFIC_ACTION_FORWARD_DNS_TO_RESOLVER: {
        error_t err = execute_dns_forward(engine, action);
        if (err != ERR_OK) {
            LOG_WARN("DNS hijack: loopback forward failed (%d), dropping", err);
            ndisapi_count_drop(engine);
        }
        break;
    }

    case TRAFFIC_ACTION_INJECT_DNS_RESPONSE:
        execute_dns_response_injection(engine, action);
        break;
    }
}

void traffic_execute_actions(ndisapi_engine_t *engine, traffic_action_t *actions,
                             size_t action_count) {
    ndisapi_send_item_t to_adapter[NDISAPI_BATCH_SIZE];
    ndisapi_send_item_t to_mstcp[NDISAPI_BATCH_SIZE];
    size_t adapter_count = 0;
    size_t mstcp_count = 0;
    size_t i;

    if (!engine || !actions || action_count == 0) return;

    for (i = 0; i < action_count; i++) {
        execute_one_action(engine, &actions[i],
                           to_adapter, &adapter_count,
                           to_mstcp, &mstcp_count);
    }

    flush_driver_sends(engine, TRAFFIC_SEND_TO_ADAPTER,
                       to_adapter, &adapter_count);
    flush_driver_sends(engine, TRAFFIC_SEND_TO_MSTCP,
                       to_mstcp, &mstcp_count);
}

void traffic_execute_action_batch(ndisapi_engine_t *engine,
                                  traffic_action_t *const *actions,
                                  size_t action_count) {
    ndisapi_send_item_t to_adapter[NDISAPI_BATCH_SIZE];
    ndisapi_send_item_t to_mstcp[NDISAPI_BATCH_SIZE];
    size_t adapter_count = 0;
    size_t mstcp_count = 0;
    size_t i;

    if (!engine || !actions || action_count == 0) return;

    for (i = 0; i < action_count; i++) {
        execute_one_action(engine, actions[i],
                           to_adapter, &adapter_count,
                           to_mstcp, &mstcp_count);
    }

    flush_driver_sends(engine, TRAFFIC_SEND_TO_ADAPTER,
                       to_adapter, &adapter_count);
    flush_driver_sends(engine, TRAFFIC_SEND_TO_MSTCP,
                       to_mstcp, &mstcp_count);
}

void traffic_execute_action(ndisapi_engine_t *engine, traffic_action_t *action) {
    traffic_execute_actions(engine, action, action ? 1U : 0U);
}
