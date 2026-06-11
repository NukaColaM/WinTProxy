/*
 * Packet parsing — extracts headers from raw Ethernet frames.
 * Manual parsing of Ethernet → IPv4 → TCP/UDP, with ndisapi C API checksums.
 */
#include "packet/context.h"
#include <stdio.h>
#include <string.h>

#define TCP_OPT_EOL         0
#define TCP_OPT_NOP         1
#define TCP_OPT_MSS         2
#define TCP_OPT_MSS_LEN     4
#define TCP_MIN_HEADER_BYTES 20U
#define DNS_HEADER_BYTES    12U
#define DNS_QR_FLAG         0x80U
#define DNS_LABEL_POINTER_MASK 0xC0U

/* === Packet parsing === */

static int packet_payload_bounds(packet_ctx_t *ctx, const uint8_t **payload,
                                 UINT *payload_len) {
    UINT ip_hdr_len;
    UINT transp_off;
    UINT transp_hdr_len;
    const uint8_t *data;
    UINT len;

    if (!ctx || !ctx->ip_hdr) return 0;

    ip_hdr_len = (UINT)ctx->ip_hdr->ip_hl * 4U;
    transp_off = ETHER_HDR_LEN + ip_hdr_len;

    if (ctx->tcp_hdr) {
        transp_hdr_len = (UINT)ctx->tcp_hdr->th_off * 4U;
    } else if (ctx->udp_hdr) {
        transp_hdr_len = 8U;
    } else {
        return 0;
    }

    if (transp_off + transp_hdr_len > ctx->packet_len) return 0;

    data = ctx->packet + transp_off + transp_hdr_len;
    len = ctx->packet_len - (transp_off + transp_hdr_len);

    if (payload) *payload = data;
    if (payload_len) *payload_len = len;
    return data && len > 0;
}

void packet_refresh_observation(packet_ctx_t *ctx) {
    packet_observation_t *obs;
    const uint8_t *payload = NULL;
    UINT payload_len = 0;

    if (!ctx) return;

    obs = &ctx->observation;
    memset(obs, 0, sizeof(*obs));
    obs->ctx = ctx;
    obs->ndis_buf = ctx->ndis_buf;
    obs->adapter_handle = ctx->adapter_handle;
    obs->src_ip = ctx->src_ip;
    obs->dst_ip = ctx->dst_ip;
    obs->src_port = ctx->src_port;
    obs->dst_port = ctx->dst_port;
    obs->protocol = ctx->protocol;
    obs->has_tcp = ctx->tcp_hdr != NULL;
    obs->has_udp = ctx->udp_hdr != NULL;
    obs->tcp_flags = ctx->tcp_hdr ? ctx->tcp_hdr->th_flags : 0;
    obs->outbound = ctx->ndis_buf &&
        ((ctx->ndis_buf->m_dwDeviceFlags & PACKET_FLAG_ON_SEND) != 0);
    obs->inbound = ctx->ndis_buf &&
        ((ctx->ndis_buf->m_dwDeviceFlags & PACKET_FLAG_ON_RECEIVE) != 0);

    if (ctx->payload_valid) {
        payload = ctx->payload_data;
        payload_len = ctx->payload_len;
    } else if (!packet_payload_bounds(ctx, &payload, &payload_len)) {
        payload = NULL;
        payload_len = 0;
    }

    obs->payload_data = payload;
    obs->payload_len = payload_len;
    obs->payload_valid = payload && payload_len > 0;

    if (ctx->dns_txid_valid) {
        obs->dns_txid = ctx->dns_txid;
        obs->dns_txid_valid = 1;
    } else if (obs->payload_valid && obs->payload_len >= 2U) {
        obs->dns_txid = (uint16_t)(((uint16_t)obs->payload_data[0] << 8) |
                                   (uint16_t)obs->payload_data[1]);
        obs->dns_txid_valid = 1;
    }
}

const packet_observation_t *packet_observe(packet_ctx_t *ctx) {
    if (!ctx) return NULL;
    packet_refresh_observation(ctx);
    return &ctx->observation;
}

packet_ctx_t *packet_observation_context(const packet_observation_t *obs) {
    return obs ? obs->ctx : NULL;
}

int packet_parse(packet_ctx_t *ctx, PINTERMEDIATE_BUFFER buf) {
    ether_header_ptr eth;
    iphdr_ptr        ip;
    UINT             eth_len;

    if (!ctx || !buf || buf->m_Length < ETHER_HDR_LEN) return 0;

    memset(ctx, 0, sizeof(*ctx));
    eth_len = buf->m_Length;

    /* Ethernet header */
    eth = (ether_header_ptr)buf->m_IBuffer;
    if (ntohs(eth->h_proto) != ETH_P_IP) return 0;  /* IPv4 only */

    /* IP header (right after Ethernet) */
    ip = (iphdr_ptr)(buf->m_IBuffer + ETHER_HDR_LEN);
    if (ip->ip_v != 4) return 0;                     /* IPv4 only */

    /* Validate IP header length */
    {
        UINT ip_hdr_len = (UINT)ip->ip_hl * 4U;
        if (ip_hdr_len < 20U) return 0;
        if (ip_hdr_len + ETHER_HDR_LEN > eth_len) return 0;
    }

    ctx->ndis_buf  = buf;
    ctx->adapter_handle = buf->m_hAdapter;
    ctx->packet    = buf->m_IBuffer;
    ctx->packet_len = eth_len;
    ctx->eth_hdr   = eth;
    ctx->ip_hdr    = ip;
    ctx->src_ip    = ip->ip_src;
    ctx->dst_ip    = ip->ip_dst;
    ctx->protocol  = ip->ip_p;

    /* TCP or UDP */
    if (ip->ip_p == 6) {  /* TCP */
        UINT ip_hdr_len = (UINT)ip->ip_hl * 4U;
        tcphdr_ptr tcp = (tcphdr_ptr)(buf->m_IBuffer + ETHER_HDR_LEN + ip_hdr_len);
        UINT tcp_hdr_len;
        if (ETHER_HDR_LEN + ip_hdr_len + 20U > eth_len) return 0;
        tcp_hdr_len = (UINT)tcp->th_off * 4U;
        if (tcp_hdr_len < 20U) return 0;

        ctx->tcp_hdr  = tcp;
        ctx->src_port = ntohs(tcp->th_sport);
        ctx->dst_port = ntohs(tcp->th_dport);
    } else if (ip->ip_p == 17) {  /* UDP */
        UINT ip_hdr_len = (UINT)ip->ip_hl * 4U;
        udphdr_ptr udp = (udphdr_ptr)(buf->m_IBuffer + ETHER_HDR_LEN + ip_hdr_len);
        if (ETHER_HDR_LEN + ip_hdr_len + 8U > eth_len) return 0;

        ctx->udp_hdr  = udp;
        ctx->src_port = ntohs(udp->uh_sport);
        ctx->dst_port = ntohs(udp->uh_dport);
    } else {
        return 0;  /* not TCP or UDP */
    }

    packet_refresh_observation(ctx);
    return 1;
}

/* === Payload extraction === */

int packet_payload(packet_ctx_t *ctx, const uint8_t **payload, UINT *payload_len) {
    if (!ctx) return 0;

    if (!ctx->payload_valid) {
        const uint8_t *data = NULL;
        UINT len = 0;

        if (!packet_payload_bounds(ctx, &data, &len)) return 0;
        ctx->payload_data  = data;
        ctx->payload_len   = len;
        ctx->payload_valid = 1;
        ctx->dns_txid_valid = 0;
        packet_refresh_observation(ctx);
    }

    if (payload)      *payload      = ctx->payload_data;
    if (payload_len)  *payload_len  = ctx->payload_len;
    return ctx->payload_data && ctx->payload_len > 0;
}

int packet_payload_observed(const packet_observation_t *obs,
                            const uint8_t **payload, UINT *payload_len) {
    if (!obs || !obs->payload_valid) {
        if (payload) *payload = NULL;
        if (payload_len) *payload_len = 0;
        return 0;
    }
    if (payload) *payload = obs->payload_data;
    if (payload_len) *payload_len = obs->payload_len;
    return obs->payload_data && obs->payload_len > 0;
}

/* === DNS TXID === */

int packet_dns_txid(packet_ctx_t *ctx, uint16_t *txid) {
    const packet_observation_t *obs;

    if (!packet_payload(ctx, NULL, NULL)) return 0;
    obs = packet_observe(ctx);
    if (!packet_dns_txid_observed(obs, txid)) return 0;

    ctx->dns_txid = obs->dns_txid;
    ctx->dns_txid_valid = 1;
    return 1;
}

int packet_dns_txid_observed(const packet_observation_t *obs, uint16_t *txid) {
    if (!obs || !obs->dns_txid_valid) {
        return 0;
    }
    if (txid) *txid = obs->dns_txid;
    return 1;
}

/* === DNS query summary (unchanged logic, adapted types) === */

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static int dns_parse_query_summary_payload(const uint8_t *dns, UINT dns_len,
                                           packet_dns_query_summary_t *summary) {
    UINT off = DNS_HEADER_BYTES;
    size_t qname_len = 0;
    uint16_t qdcount;

    if (!dns || !summary || dns_len < 2U) return 0;

    memset(summary, 0, sizeof(*summary));
    summary->txid = read_be16(dns);
    summary->txid_valid = 1;
    snprintf(summary->qname, sizeof(summary->qname), "?");
    if (dns_len < DNS_HEADER_BYTES) return 1;

    if ((dns[2] & DNS_QR_FLAG) != 0) return 1;
    qdcount = read_be16(dns + 4);
    if (qdcount == 0) return 1;

    while (off < dns_len) {
        uint8_t label_len = dns[off++];

        if (label_len == 0) break;
        if ((label_len & DNS_LABEL_POINTER_MASK) != 0) return 1;
        if (label_len > 63 || off + label_len > dns_len) return 1;

        if (qname_len > 0) {
            if (qname_len + 1 >= sizeof(summary->qname)) return 1;
            summary->qname[qname_len++] = '.';
        }

        for (uint8_t i = 0; i < label_len; i++) {
            uint8_t c = dns[off + i];
            if (qname_len + 1 >= sizeof(summary->qname)) return 1;
            if (c >= 32 && c <= 126 && c != '\\') {
                summary->qname[qname_len++] = (char)c;
            } else {
                if (qname_len + 4 >= sizeof(summary->qname)) return 1;
                snprintf(summary->qname + qname_len,
                         sizeof(summary->qname) - qname_len,
                         "\\%03u", (unsigned int)c);
                qname_len += 4;
            }
        }
        off += label_len;
    }

    if (off > dns_len || (off == dns_len && dns[off - 1] != 0)) return 1;
    if (qname_len == 0) {
        snprintf(summary->qname, sizeof(summary->qname), ".");
    } else {
        summary->qname[qname_len] = '\0';
    }

    if (off + 4U > dns_len) return 1;
    summary->qtype  = read_be16(dns + off);
    summary->qclass = read_be16(dns + off + 2U);
    summary->question_valid = 1;
    return 1;
}

int packet_dns_query_summary(packet_ctx_t *ctx, int tcp_framed,
                             packet_dns_query_summary_t *summary) {
    return packet_dns_query_summary_observed(packet_observe(ctx),
                                             tcp_framed, summary);
}

int packet_dns_query_summary_observed(const packet_observation_t *obs,
                                      int tcp_framed,
                                      packet_dns_query_summary_t *summary) {
    const uint8_t *payload = NULL;
    UINT payload_len = 0;
    const uint8_t *dns;
    UINT dns_len;

    if (!summary) return 0;
    memset(summary, 0, sizeof(*summary));

    if (!packet_payload_observed(obs, &payload, &payload_len) || !payload) return 0;

    dns = payload;
    dns_len = payload_len;
    if (tcp_framed) {
        uint16_t frame_len;
        if (payload_len < 2U) return 0;
        frame_len = read_be16(payload);
        if (frame_len == 0) return 0;
        if ((UINT)frame_len > payload_len - 2U) {
            if (payload_len - 2U < 2U) return 0;
            frame_len = (uint16_t)(payload_len - 2U);
        }
        dns = payload + 2U;
        dns_len = (UINT)frame_len;
    }

    return dns_parse_query_summary_payload(dns, dns_len, summary);
}

/* === TCP MSS clamping (unchanged logic) === */

int packet_clamp_tcp_mss(packet_ctx_t *ctx, uint16_t max_mss) {
    uint8_t *tcp_start;
    UINT tcp_header_len;
    UINT opt_off;

    if (!ctx || !ctx->tcp_hdr || !(ctx->tcp_hdr->th_flags & TH_SYN)) return 0;

    tcp_start     = (uint8_t *)ctx->tcp_hdr;
    tcp_header_len = (UINT)ctx->tcp_hdr->th_off * 4U;
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
        if (kind == TCP_OPT_NOP) { opt_off++; continue; }

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

/* === Checksum recalculation (ndisapi C API) === */

void packet_recalculate_checksums(packet_ctx_t *ctx) {
    PINTERMEDIATE_BUFFER buf;

    if (!ctx || !ctx->ndis_buf) return;

    buf = ctx->ndis_buf;

    if (ctx->tcp_hdr) {
        RecalculateTCPChecksum(buf);
    } else if (ctx->udp_hdr) {
        RecalculateUDPChecksum(buf);
    }

    RecalculateIPChecksum(buf);
}
