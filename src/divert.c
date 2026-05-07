#include "divert.h"
#include "rules.h"
#include "log.h"
#include "util.h"
#include "tcp_relay.h"
#include "udp_relay.h"
#include <stdio.h>
#include <string.h>

#include "windivert/windivert.h"

#include <winsock2.h>
#include <iphlpapi.h>

#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2
#define TCP_OPT_MSS_LEN 4
#define TCP_MIN_HEADER_BYTES 20U
#define TCP_MSS_CLAMP WTP_TCP_MSS_CLAMP
#define TCP_RELAY_SRC_PORT_MIN WTP_TCP_RELAY_SRC_PORT_MIN
#define TCP_RELAY_SRC_PORT_MAX WTP_TCP_RELAY_SRC_PORT_MAX

/* Packet context passed to handler functions */
typedef struct {
    uint8_t           *packet;
    UINT               packet_len;
    PWINDIVERT_IPHDR   ip_hdr;
    PWINDIVERT_TCPHDR  tcp_hdr;
    PWINDIVERT_UDPHDR  udp_hdr;
    uint32_t           src_ip;
    uint32_t           dst_ip;
    uint16_t           src_port;
    uint16_t           dst_port;
    uint8_t            protocol;
    const uint8_t     *dns_data;
    UINT               dns_data_len;
    int                dns_data_valid;
    uint16_t           dns_txid;
    int                dns_txid_valid;
} pkt_ctx_t;

static void counter_inc(volatile LONG64 *counter) {
    InterlockedIncrement64(counter);
}

static int divert_send_packet(divert_engine_t *engine, const void *packet, UINT packet_len,
                              WINDIVERT_ADDRESS *addr, const char *context) {
    if (WinDivertSend(engine->handle, packet, packet_len, NULL, addr)) {
        counter_inc(&engine->counters.packets_sent);
        return 1;
    }
    counter_inc(&engine->counters.send_failures);
    LOG_WARN("WinDivertSend failed (%s): err=%lu", context ? context : "packet", GetLastError());
    return 0;
}

static void set_loopback_route(divert_engine_t *engine, WINDIVERT_ADDRESS *addr) {
    addr->Outbound = 1;
    addr->Loopback = 1;
    addr->Network.IfIdx = engine->loopback_if_idx;
    addr->Network.SubIfIdx = 0;
}

static int clamp_tcp_mss(pkt_ctx_t *ctx, uint16_t max_mss) {
    uint8_t *tcp_start;
    UINT tcp_header_len;
    UINT opt_off;

    if (!ctx->tcp_hdr || !ctx->tcp_hdr->Syn) return 0;

    tcp_start = (uint8_t *)ctx->tcp_hdr;
    tcp_header_len = (UINT)ctx->tcp_hdr->HdrLength * 4U;
    if (tcp_header_len < TCP_MIN_HEADER_BYTES ||
        tcp_start < ctx->packet ||
        tcp_start + tcp_header_len > ctx->packet + ctx->packet_len) {
        return 0;
    }

    opt_off = TCP_MIN_HEADER_BYTES;
    while (opt_off < tcp_header_len) {
        uint8_t kind = tcp_start[opt_off];
        uint8_t opt_len;

        if (kind == TCP_OPT_EOL) break;
        if (kind == TCP_OPT_NOP) {
            opt_off++;
            continue;
        }

        if (opt_off + 1U >= tcp_header_len) break;
        opt_len = tcp_start[opt_off + 1U];
        if (opt_len < 2U || opt_off + opt_len > tcp_header_len) break;

        if (kind == TCP_OPT_MSS && opt_len == TCP_OPT_MSS_LEN) {
            uint16_t mss = (uint16_t)(((uint16_t)tcp_start[opt_off + 2U] << 8) |
                                      (uint16_t)tcp_start[opt_off + 3U]);
            if (mss > max_mss) {
                tcp_start[opt_off + 2U] = (uint8_t)(max_mss >> 8);
                tcp_start[opt_off + 3U] = (uint8_t)(max_mss & 0xFF);
                return 1;
            }
            return 0;
        }

        opt_off += opt_len;
    }

    return 0;
}

static uint16_t next_tcp_relay_src_port(divert_engine_t *engine) {
    LONG next = InterlockedIncrement(&engine->next_tcp_relay_src_port);
    LONG span = (LONG)TCP_RELAY_SRC_PORT_MAX - (LONG)TCP_RELAY_SRC_PORT_MIN + 1L;
    LONG offset;

    if (span <= 0) return TCP_RELAY_SRC_PORT_MIN;

    offset = (next - 1L) % span;
    if (offset < 0) {
        offset += span;
    }

    return (uint16_t)((LONG)TCP_RELAY_SRC_PORT_MIN + offset);
}

static uint32_t detect_loopback_if_idx(void) {
    DWORD if_idx = 0;
    DWORD ret = GetBestInterface(htonl(INADDR_LOOPBACK), &if_idx);
    if (ret == NO_ERROR && if_idx != 0) return if_idx;
    LOG_WARN("Could not detect loopback interface index (err=%lu); using IfIdx=1", ret);
    return 1;
}

static void tune_windivert_queue(divert_engine_t *engine) {
    WinDivertSetParam(engine->handle, WINDIVERT_PARAM_QUEUE_LENGTH, DIVERT_QUEUE_LENGTH);
    WinDivertSetParam(engine->handle, WINDIVERT_PARAM_QUEUE_TIME, DIVERT_QUEUE_TIME);
    WinDivertSetParam(engine->handle, WINDIVERT_PARAM_QUEUE_SIZE, DIVERT_QUEUE_SIZE);
    WinDivertGetParam(engine->handle, WINDIVERT_PARAM_QUEUE_LENGTH, &engine->queue_length);
    WinDivertGetParam(engine->handle, WINDIVERT_PARAM_QUEUE_TIME, &engine->queue_time);
    WinDivertGetParam(engine->handle, WINDIVERT_PARAM_QUEUE_SIZE, &engine->queue_size);
}

static int packet_dns_payload(pkt_ctx_t *ctx, const uint8_t **dns_data, UINT *dns_data_len) {
    if (!ctx->dns_data_valid) {
        PVOID data = NULL;
        UINT len = 0;
        WinDivertHelperParsePacket(ctx->packet, ctx->packet_len,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            &data, &len, NULL, NULL);
        ctx->dns_data = (const uint8_t *)data;
        ctx->dns_data_len = len;
        ctx->dns_data_valid = 1;
        ctx->dns_txid_valid = 0;
    }
    if (dns_data) *dns_data = ctx->dns_data;
    if (dns_data_len) *dns_data_len = ctx->dns_data_len;
    return ctx->dns_data && ctx->dns_data_len >= 2;
}

static int packet_dns_data(pkt_ctx_t *ctx, const uint8_t **dns_data, UINT *dns_data_len) {
    return packet_dns_payload(ctx, dns_data, dns_data_len);
}

static int packet_dns_txid(pkt_ctx_t *ctx, uint16_t *txid) {
    if (!packet_dns_payload(ctx, NULL, NULL)) return 0;
    if (!ctx->dns_txid_valid) {
        const uint8_t *p = ctx->dns_data;
        ctx->dns_txid = (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
        ctx->dns_txid_valid = 1;
    }
    if (txid) *txid = ctx->dns_txid;
    return 1;
}

/* === Packet classification ===
 * Order matches the original monolithic worker exactly — do not reorder.
 */
static int is_private_ip(uint32_t ip) {
    unsigned char *b = (unsigned char *)&ip;
    if (b[0] == 10) return 1;
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return 1;
    if (b[0] == 192 && b[1] == 168) return 1;
    if (b[0] == 169 && b[1] == 254) return 1;
    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return 1;
    return 0;
}

static pkt_type_t classify_packet(divert_engine_t *engine, pkt_ctx_t *ctx, WINDIVERT_ADDRESS *addr) {
    if (ctx->udp_hdr && addr->Outbound && addr->Loopback &&
        engine->dns_hijack->enabled &&
        ctx->src_ip == engine->dns_hijack->redirect_ip &&
        ctx->src_port == engine->dns_hijack->redirect_port)
        return PKT_DNS_RESP_LOOPBACK;

    if (!addr->Outbound) {
        if (ctx->udp_hdr && !addr->Loopback &&
            engine->dns_hijack->enabled &&
            ctx->src_ip == engine->dns_hijack->redirect_ip &&
            ctx->src_port == engine->dns_hijack->redirect_port)
            return PKT_DNS_RESP;
        return PKT_INBOUND;
    }

    if (ctx->tcp_hdr && ctx->src_port == engine->tcp_relay_port)  return PKT_TCP_RETURN;
    if (ctx->udp_hdr && ctx->src_port == engine->udp_relay_port)  return PKT_UDP_RETURN;

    if (ctx->dst_ip == engine->config->proxy.ip_addr &&
        ctx->dst_port == engine->config->proxy.port)
        return PKT_SELF_PROXY;

    if (ctx->dst_port == engine->tcp_relay_port || ctx->dst_port == engine->udp_relay_port)
        return PKT_SELF_RELAY;

    if (engine->dns_hijack->enabled &&
        ctx->dst_ip == engine->dns_hijack->redirect_ip &&
        ctx->dst_port == engine->dns_hijack->redirect_port)
        return PKT_SELF_DNS;

    if (ctx->udp_hdr && dns_hijack_is_dns_request(ctx->dst_port) && engine->dns_hijack->enabled)
        return PKT_DNS_HIJACK;

    /* Broadcast and multicast destinations can't be proxied — pass through */
    if (ctx->dst_ip == 0xFFFFFFFF) return PKT_BYPASS;
    {
        unsigned char *octets = (unsigned char *)&ctx->dst_ip;
        if (octets[0] >= 224 && octets[0] <= 239) return PKT_BYPASS;
    }

    /* Private IP ranges (RFC 1918 + link-local + CGNAT) — bypass when configured */
    if (engine->config->bypass_private_ips && is_private_ip(ctx->dst_ip))
        return PKT_BYPASS;

    return PKT_PROXY_REDIRECT;
}

/* === Handler: DNS response from loopback redirect target === */
static void handle_dns_response_loopback(divert_engine_t *engine, pkt_ctx_t *ctx,
                                          WINDIVERT_ADDRESS *addr) {
    uint32_t orig_dns_ip, cli_ip;
    uint16_t orig_dns_port;
    uint32_t orig_if_idx, orig_sub_if_idx;
    uint16_t dns_txid;

    if (!packet_dns_txid(ctx, &dns_txid)) {
        LOG_PACKET("DNS response (loopback): malformed payload, passing through");
        divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "DNS response loopback malformed");
        return;
    }

    if (dns_hijack_rewrite_response(engine->dns_hijack, &orig_dns_ip, &orig_dns_port,
                                     ctx->dst_port, dns_txid,
                                     &cli_ip, &orig_if_idx, &orig_sub_if_idx)) {
        char orig_str[16], cli_str[16], src_str[16];
        ip_to_str(orig_dns_ip, orig_str, sizeof(orig_str));
        ip_to_str(cli_ip, cli_str, sizeof(cli_str));
        ip_to_str(ctx->src_ip, src_str, sizeof(src_str));
        LOG_PACKET("DNS response (loopback): src %s:%u -> %s:%u, dst -> %s, IfIdx=%lu",
            src_str, ctx->src_port, orig_str, orig_dns_port, cli_str, (unsigned long)orig_if_idx);
        ctx->ip_hdr->SrcAddr = orig_dns_ip;
        ctx->udp_hdr->SrcPort = htons(orig_dns_port);
        ctx->ip_hdr->DstAddr = cli_ip;
        addr->Outbound = 0;
        addr->Loopback = 0;
        addr->Network.IfIdx = orig_if_idx;
        addr->Network.SubIfIdx = orig_sub_if_idx;
        WinDivertHelperCalcChecksums(ctx->packet, ctx->packet_len, addr, 0);
    }
    divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "DNS response loopback");
}

/* === Handler: inbound packets (with optional DNS response rewrite) === */
static void handle_inbound(divert_engine_t *engine, pkt_ctx_t *ctx,
                            WINDIVERT_ADDRESS *addr, pkt_type_t type) {
    if (type == PKT_DNS_RESP) {
        uint32_t orig_dns_ip;
        uint16_t orig_dns_port;
        uint16_t dns_txid;
        if (packet_dns_txid(ctx, &dns_txid) &&
            dns_hijack_rewrite_response(engine->dns_hijack, &orig_dns_ip, &orig_dns_port,
                                         ctx->dst_port, dns_txid, NULL, NULL, NULL)) {
            ctx->ip_hdr->SrcAddr = orig_dns_ip;
            ctx->udp_hdr->SrcPort = htons(orig_dns_port);
            WinDivertHelperCalcChecksums(ctx->packet, ctx->packet_len, addr, 0);
        }
    }
    divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "inbound");
}

/* === Handler: TCP/UDP return path (shared logic) === */
static void handle_return_path(divert_engine_t *engine, pkt_ctx_t *ctx,
                                WINDIVERT_ADDRESS *addr, pkt_type_t type) {
    uint8_t proto_num = (type == PKT_TCP_RETURN) ? 6 : 17;
    conntrack_entry_t entry;
    error_t err;

    if (type == PKT_TCP_RETURN) {
        err = conntrack_get_full_key(engine->conntrack, LOOPBACK_ADDR, ctx->dst_port,
                                     LOOPBACK_ADDR, ctx->src_port, proto_num, &entry);
    } else {
        err = conntrack_get_full(engine->conntrack, ctx->dst_ip, ctx->dst_port, proto_num, &entry);
    }
    if (err != ERR_OK) {
        LOG_PACKET("%s return: no conntrack for dst_port %u",
            (type == PKT_TCP_RETURN) ? "TCP" : "UDP", ctx->dst_port);
        counter_inc(&engine->counters.packets_dropped);
        return;
    }

    ctx->ip_hdr->SrcAddr = entry.orig_dst_ip;
    ctx->ip_hdr->DstAddr = entry.src_ip;

    if (type == PKT_TCP_RETURN)
        ctx->tcp_hdr->SrcPort = htons(entry.orig_dst_port);
    else
        ctx->udp_hdr->SrcPort = htons(entry.orig_dst_port);

    if (type == PKT_TCP_RETURN) {
        ctx->tcp_hdr->DstPort = htons(entry.client_port);
    }

    if (type == PKT_TCP_RETURN) {
        clamp_tcp_mss(ctx, TCP_MSS_CLAMP);
    }

    if (type == PKT_TCP_RETURN) {
        conntrack_touch_key(engine->conntrack, entry.key_src_ip, entry.src_port,
                            entry.key_dst_ip, entry.key_dst_port, proto_num);
        conntrack_touch_key(engine->conntrack, LOOPBACK_ADDR, entry.relay_src_port,
                            LOOPBACK_ADDR, engine->tcp_relay_port, proto_num);
    } else {
        conntrack_touch(engine->conntrack, entry.key_src_ip, ctx->dst_port, proto_num);
        if (entry.src_ip != entry.key_src_ip) {
            conntrack_touch(engine->conntrack, entry.src_ip, ctx->dst_port, proto_num);
        }
    }
    addr->Outbound = 0;
    addr->Loopback = 0;
    addr->Network.IfIdx = entry.if_idx;
    addr->Network.SubIfIdx = entry.sub_if_idx;
    WinDivertHelperCalcChecksums(ctx->packet, ctx->packet_len, addr, 0);

    char orig_dst_str[16], orig_src_str[16];
    ip_to_str(entry.orig_dst_ip, orig_dst_str, sizeof(orig_dst_str));
    ip_to_str(entry.src_ip, orig_src_str, sizeof(orig_src_str));
    LOG_PACKET("%s return: rewrite 127.0.0.1:%u -> %s:%u, dst -> %s, IfIdx=%lu",
        (type == PKT_TCP_RETURN) ? "TCP" : "UDP",
        (type == PKT_TCP_RETURN) ? engine->tcp_relay_port : engine->udp_relay_port,
        orig_dst_str, entry.orig_dst_port, orig_src_str, (unsigned long)entry.if_idx);

    divert_send_packet(engine, ctx->packet, ctx->packet_len, addr,
                       (type == PKT_TCP_RETURN) ? "TCP return" : "UDP return");
}

/* === Handler: DNS hijacking (non-loopback rewrite or loopback socket forward) === */
static void handle_dns_hijack(divert_engine_t *engine, pkt_ctx_t *ctx,
                               WINDIVERT_ADDRESS *addr) {
    const uint8_t *dns_data = NULL;
    UINT dns_data_len = 0;
    uint16_t dns_txid = 0;

    packet_dns_data(ctx, &dns_data, &dns_data_len);
    if (!dns_data || dns_data_len < 2 || !packet_dns_txid(ctx, &dns_txid)) {
        LOG_PACKET("DNS hijack: malformed DNS payload, passing through");
        divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "DNS malformed pass");
        return;
    }

    if (engine->dns_hijack->use_socket_fwd) {
        error_t err = dns_hijack_forward_query(engine->dns_hijack,
            dns_data, (int)dns_data_len,
            ctx->src_port, ctx->dst_ip, ctx->dst_port,
            ctx->src_ip, addr->Network.IfIdx, addr->Network.SubIfIdx);
        if (err != ERR_OK) {
            LOG_WARN("DNS hijack: loopback forward failed (%d), passing original query", err);
            divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "DNS forward fallback");
        }
        return;
    }

    uint32_t new_dst_ip = ctx->dst_ip;
    uint16_t new_dst_port = ctx->dst_port;
    if (dns_hijack_rewrite_request(engine->dns_hijack, &new_dst_ip, &new_dst_port,
                                    ctx->src_port, dns_txid,
                                    ctx->dst_ip, ctx->dst_port,
                                    ctx->src_ip, addr->Network.IfIdx, addr->Network.SubIfIdx) == 1) {
        ctx->ip_hdr->DstAddr = new_dst_ip;
        ctx->udp_hdr->DstPort = htons(new_dst_port);
        WinDivertHelperCalcChecksums(ctx->packet, ctx->packet_len, addr, 0);
        divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "DNS hijack");
    } else {
        LOG_WARN("DNS hijack: failed to store NAT entry, passing original query");
        divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "DNS hijack fallback");
    }
}

/* === Helper: forward UDP payload to relay via real socket === */
static void proxy_redirect_udp_forward(divert_engine_t *engine, pkt_ctx_t *ctx) {
    PVOID udp_data = NULL;
    UINT udp_data_len = 0;
    WinDivertHelperParsePacket(ctx->packet, ctx->packet_len,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        &udp_data, &udp_data_len, NULL, NULL);
    if (!udp_data || udp_data_len == 0) {
        LOG_WARN("UDP PROXY: failed to extract payload");
        return;
    }

    if (udp_data_len > WTP_UDP_BUFFER_SIZE) {
        LOG_WARN("UDP PROXY: payload too large: %u", udp_data_len);
        return;
    }

    uint8_t framed[6 + WTP_UDP_BUFFER_SIZE];
    int framed_len = (int)(2U + udp_data_len);
    framed_len = (int)(6U + udp_data_len);
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
    if (fwd == SOCKET_ERROR)
        LOG_WARN("UDP fwd sendto failed: %d", WSAGetLastError());
    else {
        counter_inc(&engine->counters.udp_forwarded);
        LOG_PACKET("UDP fwd: sent %u bytes (port %u) to relay", udp_data_len, ctx->src_port);
    }
}

static error_t add_proxy_conntrack(divert_engine_t *engine, pkt_ctx_t *ctx,
                                   WINDIVERT_ADDRESS *addr, uint32_t pid,
                                   const char *proc_name) {
    conntrack_entry_t existing;
    uint16_t relay_src_port = ctx->src_port;
    error_t err;

    if (ctx->tcp_hdr) {
        if (conntrack_get_full_key(engine->conntrack,
                                   ctx->src_ip, ctx->src_port,
                                   ctx->dst_ip, ctx->dst_port,
                                   ctx->protocol, &existing) == ERR_OK &&
            existing.relay_src_port != 0) {
            relay_src_port = existing.relay_src_port;
        } else {
            relay_src_port = next_tcp_relay_src_port(engine);
        }

        err = conntrack_add_key_full(engine->conntrack,
                                     ctx->src_ip, ctx->src_port,
                                     ctx->dst_ip, ctx->dst_port,
                                     ctx->src_ip, ctx->src_port,
                                     ctx->dst_ip, ctx->dst_port,
                                     ctx->protocol, pid, proc_name,
                                     addr->Network.IfIdx, addr->Network.SubIfIdx,
                                     relay_src_port);
        if (err != ERR_OK) return err;

        err = conntrack_add_key_full(engine->conntrack,
                                     LOOPBACK_ADDR, relay_src_port,
                                     LOOPBACK_ADDR, engine->tcp_relay_port,
                                     ctx->src_ip, ctx->src_port,
                                     ctx->dst_ip, ctx->dst_port,
                                     ctx->protocol, pid, proc_name,
                                     addr->Network.IfIdx, addr->Network.SubIfIdx,
                                     relay_src_port);
        if (err != ERR_OK) {
            conntrack_remove_key(engine->conntrack, ctx->src_ip, ctx->src_port,
                                 ctx->dst_ip, ctx->dst_port, ctx->protocol);
            return err;
        }

        if (conntrack_get_full_key(engine->conntrack,
                                   ctx->src_ip, ctx->src_port,
                                   ctx->dst_ip, ctx->dst_port,
                                   ctx->protocol, &existing) == ERR_OK &&
            existing.relay_src_port != 0 &&
            existing.relay_src_port != relay_src_port) {
            conntrack_remove_key(engine->conntrack, LOOPBACK_ADDR, relay_src_port,
                                 LOOPBACK_ADDR, engine->tcp_relay_port, ctx->protocol);
            relay_src_port = existing.relay_src_port;
        }

        ctx->tcp_hdr->SrcPort = htons(relay_src_port);
    } else if (ctx->udp_hdr) {
        err = conntrack_add(engine->conntrack, ctx->src_port, ctx->src_ip,
                            ctx->dst_ip, ctx->dst_port, ctx->protocol,
                            pid, proc_name,
                            addr->Network.IfIdx, addr->Network.SubIfIdx);
        if (err != ERR_OK) return err;

        err = conntrack_add_key(engine->conntrack, LOOPBACK_ADDR, ctx->src_port,
                                ctx->src_ip, ctx->dst_ip, ctx->dst_port,
                                ctx->protocol, pid, proc_name,
                                addr->Network.IfIdx, addr->Network.SubIfIdx);
        if (err != ERR_OK) {
            conntrack_remove(engine->conntrack, ctx->src_ip, ctx->src_port, ctx->protocol);
            return err;
        }
    }

    return err;
}

/* === Helper: non-SYN TCP that is tracked — redirect to relay === */
static int proxy_redirect_tcp_non_syn_tracked(divert_engine_t *engine, pkt_ctx_t *ctx,
                                               WINDIVERT_ADDRESS *addr) {
    conntrack_entry_t entry;
    if (conntrack_get_full_key(engine->conntrack, ctx->src_ip, ctx->src_port,
                               ctx->dst_ip, ctx->dst_port, 6, &entry) != ERR_OK)
        return 0;

    ctx->ip_hdr->SrcAddr = LOOPBACK_ADDR;
    ctx->ip_hdr->DstAddr = LOOPBACK_ADDR;
    ctx->tcp_hdr->SrcPort = htons(entry.relay_src_port);
    ctx->tcp_hdr->DstPort = htons(engine->tcp_relay_port);
    set_loopback_route(engine, addr);
    WinDivertHelperCalcChecksums(ctx->packet, ctx->packet_len, addr, 0);
    divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "TCP tracked non-SYN");
    return 1;
}

static void handle_tcp_non_syn_untracked(divert_engine_t *engine, pkt_ctx_t *ctx,
                                         WINDIVERT_ADDRESS *addr) {
    char proc_name[256] = {0};
    uint32_t pid;
    rule_action_t action;

    pid = proc_lookup_tcp_retry(engine->proc_lookup, ctx->src_ip, ctx->src_port,
                                proc_name, sizeof(proc_name));
    if (pid > 0 && proc_is_self(engine->proc_lookup, pid)) {
        divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "self pass");
        return;
    }

    action = rules_match_ex(engine->config->rules, engine->config->rule_count,
                            engine->config->default_action,
                            proc_name, ctx->dst_ip, ctx->dst_port, ctx->protocol,
                            NULL);

    if (action == RULE_ACTION_DIRECT) {
        divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "TCP non-SYN direct");
        return;
    }

    if (action == RULE_ACTION_BLOCK) {
        counter_inc(&engine->counters.packets_dropped);
        return;
    }

    /*
     * A proxied TCP packet without conntrack cannot be safely redirected:
     * there is no relay source port to map the return path. Passing it
     * through would leak that flow outside the proxy.
     */
    counter_inc(&engine->counters.packets_dropped);
}

/* === Handler: proxy redirect (process lookup, rules, relay injection) === */
static void handle_proxy_redirect(divert_engine_t *engine, pkt_ctx_t *ctx,
                                   WINDIVERT_ADDRESS *addr) {
    char proc_name[256] = {0};
    char dst_str[16];
    char rule_str[16];
    uint32_t pid = 0;
    int matched_rule_id = 0;

    /* Process lookup */
    if (ctx->tcp_hdr) {
        if (ctx->tcp_hdr->Syn && !ctx->tcp_hdr->Ack) {
            pid = proc_lookup_tcp(engine->proc_lookup, ctx->src_ip, ctx->src_port,
                                  proc_name, sizeof(proc_name));
        } else {
            if (proxy_redirect_tcp_non_syn_tracked(engine, ctx, addr))
                return;
            handle_tcp_non_syn_untracked(engine, ctx, addr);
            return;
        }
    } else {
        pid = proc_lookup_udp(engine->proc_lookup, ctx->src_ip, ctx->src_port,
                              proc_name, sizeof(proc_name));
    }

    /* Self-exclusion */
    if (pid > 0 && proc_is_self(engine->proc_lookup, pid)) {
        LOG_DEBUG("SELF: pid=%u %s, passing through", pid, proc_name);
        divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "self pass");
        return;
    }

    ip_to_str(ctx->dst_ip, dst_str, sizeof(dst_str));

    if (pid == 0) {
        if (ctx->tcp_hdr) {
            pid = proc_lookup_tcp_retry(engine->proc_lookup, ctx->src_ip, ctx->src_port,
                                        proc_name, sizeof(proc_name));
        } else {
            pid = proc_lookup_udp_retry(engine->proc_lookup, ctx->src_ip, ctx->src_port,
                                        proc_name, sizeof(proc_name));
        }
        if (pid > 0 && proc_is_self(engine->proc_lookup, pid)) {
            LOG_DEBUG("SELF: pid=%u %s, passing through", pid, proc_name);
            divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "self pass");
            return;
        }
    }

    /* Rule matching */
    rule_action_t action = rules_match_ex(engine->config->rules, engine->config->rule_count,
                                          engine->config->default_action,
                                          proc_name, ctx->dst_ip, ctx->dst_port, ctx->protocol,
                                          &matched_rule_id);
    if (matched_rule_id > 0) snprintf(rule_str, sizeof(rule_str), "#%d", matched_rule_id);
    else safe_str_copy(rule_str, sizeof(rule_str), "default");

    if (action == RULE_ACTION_BLOCK) {
        LOG_DEBUG("BLOCK: rule=%s %s [%u] -> %s:%u (%s)",
            rule_str, proc_name[0] ? proc_name : "?", pid, dst_str, ctx->dst_port,
            ctx->protocol == 6 ? "TCP" : "UDP");
        return;
    }

    if (action == RULE_ACTION_DIRECT) {
        LOG_DEBUG("DIRECT: rule=%s %s [%u] -> %s:%u (%s)",
            rule_str, proc_name[0] ? proc_name : "?", pid, dst_str, ctx->dst_port,
            ctx->protocol == 6 ? "TCP" : "UDP");
        divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "direct");
        return;
    }

    /* PROXY action */
    uint16_t relay_port = (ctx->protocol == 6) ? engine->tcp_relay_port : engine->udp_relay_port;
    LOG_DEBUG("PROXY: rule=%s %s [%u] -> %s:%u via relay :%u (%s) IfIdx=%lu",
        rule_str, proc_name[0] ? proc_name : "?", pid, dst_str, ctx->dst_port, relay_port,
        ctx->protocol == 6 ? "TCP" : "UDP", (unsigned long)addr->Network.IfIdx);

    if (add_proxy_conntrack(engine, ctx, addr, pid, proc_name) != ERR_OK) {
        LOG_WARN("PROXY: conntrack unavailable for %s [%u] -> %s:%u (%s), dropping",
            proc_name[0] ? proc_name : "?", pid, dst_str, ctx->dst_port,
            ctx->protocol == 6 ? "TCP" : "UDP");
        counter_inc(&engine->counters.packets_dropped);
        return;
    }

    if (ctx->tcp_hdr) {
        clamp_tcp_mss(ctx, TCP_MSS_CLAMP);
        ctx->ip_hdr->SrcAddr = LOOPBACK_ADDR;
        ctx->ip_hdr->DstAddr = LOOPBACK_ADDR;
        ctx->tcp_hdr->DstPort = htons(relay_port);
        set_loopback_route(engine, addr);
        WinDivertHelperCalcChecksums(ctx->packet, ctx->packet_len, addr, 0);
        divert_send_packet(engine, ctx->packet, ctx->packet_len, addr, "TCP PROXY redirect");
    } else {
        proxy_redirect_udp_forward(engine, ctx);
    }
}

/* === Main worker loop (dispatcher) === */
static DWORD WINAPI divert_worker_proc(LPVOID param) {
    divert_engine_t *engine = (divert_engine_t *)param;
    uint8_t packet[DIVERT_MAX_PACKET_SIZE];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    while (engine->running) {
        if (!WinDivertRecv(engine->handle, packet, sizeof(packet), &packet_len, &addr)) {
            if (!engine->running) break;
            DWORD err = GetLastError();
            if (err == ERROR_NO_DATA || err == ERROR_INSUFFICIENT_BUFFER) continue;
            LOG_ERROR("WinDivertRecv failed: %lu", err);
            continue;
        }
        counter_inc(&engine->counters.packets_recv);

        PWINDIVERT_IPHDR ip_hdr = NULL;
        PWINDIVERT_TCPHDR tcp_hdr = NULL;
        PWINDIVERT_UDPHDR udp_hdr = NULL;
        WinDivertHelperParsePacket(packet, packet_len,
            &ip_hdr, NULL, NULL, NULL, NULL, &tcp_hdr, &udp_hdr,
            NULL, NULL, NULL, NULL);

        if (!ip_hdr) {
            divert_send_packet(engine, packet, packet_len, &addr, "non-IP pass");
            continue;
        }

        uint16_t src_port = 0, dst_port = 0;
        if (tcp_hdr) {
            src_port = ntohs(tcp_hdr->SrcPort);
            dst_port = ntohs(tcp_hdr->DstPort);
        } else if (udp_hdr) {
            src_port = ntohs(udp_hdr->SrcPort);
            dst_port = ntohs(udp_hdr->DstPort);
        } else {
            divert_send_packet(engine, packet, packet_len, &addr, "non-TCP/UDP pass");
            continue;
        }

        pkt_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.packet = packet;
        ctx.packet_len = packet_len;
        ctx.ip_hdr = ip_hdr;
        ctx.tcp_hdr = tcp_hdr;
        ctx.udp_hdr = udp_hdr;
        ctx.src_ip = ip_hdr->SrcAddr;
        ctx.dst_ip = ip_hdr->DstAddr;
        ctx.src_port = src_port;
        ctx.dst_port = dst_port;
        ctx.protocol = ip_hdr->Protocol;

        pkt_type_t type = classify_packet(engine, &ctx, &addr);

        switch (type) {
        case PKT_DNS_RESP_LOOPBACK:
            handle_dns_response_loopback(engine, &ctx, &addr);
            break;
        case PKT_INBOUND:
        case PKT_DNS_RESP:
            handle_inbound(engine, &ctx, &addr, type);
            break;
        case PKT_TCP_RETURN:
        case PKT_UDP_RETURN:
            handle_return_path(engine, &ctx, &addr, type);
            break;
        case PKT_SELF_PROXY:
        case PKT_SELF_RELAY:
        case PKT_SELF_DNS:
        case PKT_BYPASS:
            divert_send_packet(engine, packet, packet_len, &addr, "bypass");
            break;
        case PKT_DNS_HIJACK:
            handle_dns_hijack(engine, &ctx, &addr);
            break;
        case PKT_PROXY_REDIRECT:
            handle_proxy_redirect(engine, &ctx, &addr);
            break;
        }
    }

    return 0;
}

static void divert_close_handle(divert_engine_t *engine) {
    if (engine->handle && engine->handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(engine->handle);
    }
    engine->handle = INVALID_HANDLE_VALUE;
}

static void divert_close_udp_socket(divert_engine_t *engine) {
    if (engine->udp_fwd_sock != INVALID_SOCKET) {
        closesocket(engine->udp_fwd_sock);
    }
    engine->udp_fwd_sock = INVALID_SOCKET;
}

static void divert_join_workers(divert_engine_t *engine) {
    for (int i = 0; i < DIVERT_WORKER_COUNT; i++) {
        if (engine->workers[i]) {
            WaitForSingleObject(engine->workers[i], 5000);
            CloseHandle(engine->workers[i]);
            engine->workers[i] = NULL;
        }
    }
}

static error_t divert_start_fail(divert_engine_t *engine, dns_hijack_t *dns_hijack,
                                 int dns_forwarder_started, error_t err) {
    engine->running = 0;
    if (dns_forwarder_started) {
        dns_hijack_shutdown(dns_hijack);
    }
    divert_close_handle(engine);
    divert_close_udp_socket(engine);
    divert_join_workers(engine);
    return err;
}

error_t divert_start(divert_engine_t *engine, app_config_t *config,
                    conntrack_t *conntrack, proc_lookup_t *proc_lookup,
                    dns_hijack_t *dns_hijack,
                    uint16_t tcp_relay_port, uint16_t udp_relay_port) {
    int dns_forwarder_started = 0;

    memset(engine, 0, sizeof(*engine));
    engine->handle = INVALID_HANDLE_VALUE;
    engine->config = config;
    engine->conntrack = conntrack;
    engine->proc_lookup = proc_lookup;
    engine->dns_hijack = dns_hijack;
    engine->tcp_relay_port = tcp_relay_port;
    engine->udp_relay_port = udp_relay_port;
    engine->loopback_if_idx = detect_loopback_if_idx();
    engine->running = 1;
    engine->udp_fwd_sock = INVALID_SOCKET;

    /*
     * WinDivert filter — three capture clauses:
     * 1. Outbound non-loopback TCP (all ports) — main TCP interception
     * 2. Outbound non-loopback UDP except system ports (DHCP 67, NTP 123,
     *    IKE 500, IPsec NAT-T 4500) — UDP interception
     * 3. Outbound loopback from relay ports — return path rewriting
     *    (+ optional inbound DNS response clause appended below)
     *
     * 224.0.0.0/3 (multicast + class-E reserved + broadcast) is excluded
     * from clauses 1+2 — those packets never reach user-mode.
     */
    char filter[1024];
    snprintf(filter, sizeof(filter),
        "((outbound and ip and !loopback and tcp) or "
        "(outbound and ip and !loopback and udp and "
        "udp.DstPort != 67 and udp.DstPort != 123 and "
        "udp.DstPort != 500 and udp.SrcPort != 500 and "
        "udp.DstPort != 4500 and udp.SrcPort != 4500)) "
        "and (ip.DstAddr < 224.0.0.0) "
        "or "
        "(outbound and ip and loopback and "
        "(tcp.SrcPort == %u or udp.SrcPort == %u))",
        engine->tcp_relay_port, engine->udp_relay_port);

    if (dns_hijack->enabled) {
        char dns_filter[512];
        uint8_t *ip_bytes = (uint8_t *)&dns_hijack->redirect_ip;

        if (dns_hijack->redirect_ip == LOOPBACK_ADDR) {
            /* Loopback DNS uses socket-based forwarding — no filter needed */
            dns_filter[0] = '\0';
        } else {
            /* Non-loopback DNS server: capture inbound responses by IP */
            snprintf(dns_filter, sizeof(dns_filter),
                " or (inbound and ip and udp and ip.SrcAddr == %u.%u.%u.%u and udp.SrcPort == %u)",
                ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                dns_hijack->redirect_port);
        }
        strncat(filter, dns_filter, sizeof(filter) - strlen(filter) - 1);
    }

    LOG_DEBUG("WinDivert filter: %s", filter);

    engine->handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (engine->handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        LOG_ERROR("WinDivertOpen failed: %lu", err);
        if (err == 5) LOG_ERROR("Access denied — run as Administrator");
        if (err == 577) LOG_ERROR("Driver not signed — install WinDivert driver");
        engine->running = 0;
        return ERR_PERMISSION;
    }

    tune_windivert_queue(engine);
    LOG_INFO("WinDivert queue: length=%llu time=%llums size=%llu bytes; loopback IfIdx=%lu",
             (unsigned long long)engine->queue_length,
             (unsigned long long)engine->queue_time,
             (unsigned long long)engine->queue_size,
             (unsigned long)engine->loopback_if_idx);

    /* UDP forwarding socket: sends intercepted UDP payloads to the relay via real loopback */
    engine->udp_fwd_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (engine->udp_fwd_sock == INVALID_SOCKET) {
        LOG_ERROR("UDP fwd socket: socket() failed: %d", WSAGetLastError());
        return divert_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_NETWORK);
    }
    {
        struct sockaddr_in bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind_addr.sin_port = 0;
        if (bind(engine->udp_fwd_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
            LOG_ERROR("UDP fwd socket: bind() failed: %d", WSAGetLastError());
            return divert_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_NETWORK);
        }
        struct sockaddr_in local;
        int local_len = sizeof(local);
        if (getsockname(engine->udp_fwd_sock, (struct sockaddr *)&local, &local_len) == SOCKET_ERROR) {
            LOG_ERROR("UDP fwd socket: getsockname() failed: %d", WSAGetLastError());
            return divert_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_NETWORK);
        }
        LOG_INFO("UDP forwarding socket bound to 127.0.0.1:%u", ntohs(local.sin_port));
    }

    if (dns_hijack->use_socket_fwd) {
        if (dns_hijack_start_forwarder(dns_hijack, engine->handle) != ERR_OK) {
            LOG_ERROR("Failed to start DNS forwarder");
            return divert_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_GENERIC);
        }
        dns_forwarder_started = 1;
    }

    for (int i = 0; i < DIVERT_WORKER_COUNT; i++) {
        engine->workers[i] = CreateThread(NULL, 0, divert_worker_proc, engine, 0, NULL);
        if (!engine->workers[i]) {
            LOG_ERROR("Failed to create WinDivert worker thread %d", i);
            return divert_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_GENERIC);
        }
    }

    LOG_INFO("WinDivert engine started with %d workers", DIVERT_WORKER_COUNT);
    return ERR_OK;
}

void divert_stop(divert_engine_t *engine) {
    engine->running = 0;
    if (engine->dns_hijack && engine->dns_hijack->use_socket_fwd) {
        dns_hijack_shutdown(engine->dns_hijack);
    }
    divert_close_handle(engine);
    divert_close_udp_socket(engine);
    divert_join_workers(engine);

    LOG_INFO("WinDivert engine stopped");
}

void divert_snapshot_counters(divert_engine_t *engine, divert_counters_t *out) {
    memset(out, 0, sizeof(*out));
    out->packets_recv = InterlockedExchange64(&engine->counters.packets_recv, 0);
    out->packets_sent = InterlockedExchange64(&engine->counters.packets_sent, 0);
    out->packets_dropped = InterlockedExchange64(&engine->counters.packets_dropped, 0);
    out->send_failures = InterlockedExchange64(&engine->counters.send_failures, 0);
    out->udp_forwarded = InterlockedExchange64(&engine->counters.udp_forwarded, 0);
}
