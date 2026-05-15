#include "packet/context.h"
#include <string.h>

#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2
#define TCP_OPT_MSS_LEN 4
#define TCP_MIN_HEADER_BYTES 20U

int packet_parse(packet_ctx_t *ctx, uint8_t *packet, UINT packet_len) {
    PWINDIVERT_IPHDR ip_hdr = NULL;
    PWINDIVERT_TCPHDR tcp_hdr = NULL;
    PWINDIVERT_UDPHDR udp_hdr = NULL;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    if (!ctx || !packet) return 0;

    memset(ctx, 0, sizeof(*ctx));
    WinDivertHelperParsePacket(packet, packet_len,
        &ip_hdr, NULL, NULL, NULL, NULL, &tcp_hdr, &udp_hdr,
        NULL, NULL, NULL, NULL);

    if (!ip_hdr) return 0;

    if (tcp_hdr) {
        src_port = ntohs(tcp_hdr->SrcPort);
        dst_port = ntohs(tcp_hdr->DstPort);
    } else if (udp_hdr) {
        src_port = ntohs(udp_hdr->SrcPort);
        dst_port = ntohs(udp_hdr->DstPort);
    } else {
        return 0;
    }

    ctx->packet = packet;
    ctx->packet_len = packet_len;
    ctx->ip_hdr = ip_hdr;
    ctx->tcp_hdr = tcp_hdr;
    ctx->udp_hdr = udp_hdr;
    ctx->src_ip = ip_hdr->SrcAddr;
    ctx->dst_ip = ip_hdr->DstAddr;
    ctx->src_port = src_port;
    ctx->dst_port = dst_port;
    ctx->protocol = ip_hdr->Protocol;
    return 1;
}

int packet_payload(packet_ctx_t *ctx, const uint8_t **payload, UINT *payload_len) {
    if (!ctx) return 0;

    if (!ctx->payload_valid) {
        PVOID data = NULL;
        UINT len = 0;
        WinDivertHelperParsePacket(ctx->packet, ctx->packet_len,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            &data, &len, NULL, NULL);
        ctx->payload_data = (const uint8_t *)data;
        ctx->payload_len = len;
        ctx->payload_valid = 1;
        ctx->dns_txid_valid = 0;
    }

    if (payload) *payload = ctx->payload_data;
    if (payload_len) *payload_len = ctx->payload_len;
    return ctx->payload_data && ctx->payload_len > 0;
}

int packet_dns_txid(packet_ctx_t *ctx, uint16_t *txid) {
    if (!packet_payload(ctx, NULL, NULL)) return 0;
    if (!ctx->payload_data || ctx->payload_len < 2) return 0;

    if (!ctx->dns_txid_valid) {
        const uint8_t *p = ctx->payload_data;
        ctx->dns_txid = (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
        ctx->dns_txid_valid = 1;
    }
    if (txid) *txid = ctx->dns_txid;
    return 1;
}

int packet_clamp_tcp_mss(packet_ctx_t *ctx, uint16_t max_mss) {
    uint8_t *tcp_start;
    UINT tcp_header_len;
    UINT opt_off;

    if (!ctx || !ctx->tcp_hdr || !ctx->tcp_hdr->Syn) return 0;

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

void packet_recalculate_checksums(packet_ctx_t *ctx, WINDIVERT_ADDRESS *addr) {
    if (!ctx || !addr) return;
    WinDivertHelperCalcChecksums(ctx->packet, ctx->packet_len, addr, 0);
}
