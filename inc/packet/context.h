/*
 * Packet parsing context — extracted header fields from a raw Ethernet frame
 * using standard BSD-style structures from net/headers.h.
 */
#ifndef WINTPROXY_PACKET_CONTEXT_H
#define WINTPROXY_PACKET_CONTEXT_H

#include <stdint.h>
#include "net/headers.h"
#include "ndisapi/ndisapi.h"    /* for INTERMEDIATE_BUFFER */

#ifdef __cplusplus
extern "C" {
#endif

#define PACKET_DNS_QNAME_MAX 256

typedef struct {
    char     qname[PACKET_DNS_QNAME_MAX];
    uint16_t txid;
    uint16_t qtype;
    uint16_t qclass;
    int      txid_valid;
    int      question_valid;
} packet_dns_query_summary_t;

/*
 * Parsed packet context.
 * Fields are extracted once during packet_parse() and cached.
 * The original INTERMEDIATE_BUFFER pointer is kept for checksum
 * recalculation (ndisapi C API needs it).
 */
typedef struct {
    /* Raw data */
    uint8_t              *packet;        /* pointer to m_IBuffer (Ethernet frame start) */
    UINT                  packet_len;    /* m_Length (total frame length) */
    PINTERMEDIATE_BUFFER ndis_buf;      /* original buffer for direction + checksums */

    /* Parsed headers */
    ether_header_ptr      eth_hdr;       /* Ethernet header */
    iphdr_ptr             ip_hdr;        /* IPv4 header */
    tcphdr_ptr            tcp_hdr;       /* TCP header (NULL if UDP/other) */
    udphdr_ptr            udp_hdr;       /* UDP header (NULL if TCP/other) */

    /* Extracted values (host byte order) */
    uint32_t              src_ip;
    uint32_t              dst_ip;
    uint16_t              src_port;
    uint16_t              dst_port;
    uint8_t               protocol;      /* IP protocol: 6=TCP, 17=UDP */

    /* Cached payload */
    const uint8_t        *payload_data;
    UINT                  payload_len;
    int                   payload_valid;

    /* Cached DNS fields */
    uint16_t              dns_txid;
    int                   dns_txid_valid;

    /* Adapter info (from m_hAdapter — set by packet_parse) */
    HANDLE                adapter_handle;
    char                  adapter_name[64];
} packet_ctx_t;

/* === Direction helpers (convenience macros for ndisapi flags) === */
#define PKT_IS_OUTBOUND(ctx)  ((ctx)->ndis_buf && \
    ((ctx)->ndis_buf->m_dwDeviceFlags & PACKET_FLAG_ON_SEND))
#define PKT_IS_INBOUND(ctx)   ((ctx)->ndis_buf && \
    ((ctx)->ndis_buf->m_dwDeviceFlags & PACKET_FLAG_ON_RECEIVE))

/* === Parse and query === */
int  packet_parse(packet_ctx_t *ctx, PINTERMEDIATE_BUFFER buf);
int  packet_payload(packet_ctx_t *ctx, const uint8_t **payload, UINT *payload_len);
int  packet_dns_txid(packet_ctx_t *ctx, uint16_t *txid);
int  packet_dns_query_summary(packet_ctx_t *ctx, int tcp_framed,
                               packet_dns_query_summary_t *summary);
int  packet_clamp_tcp_mss(packet_ctx_t *ctx, uint16_t max_mss);

/* === Checksum recalculation (uses ndisapi C API) === */
void packet_recalculate_checksums(packet_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* WINTPROXY_PACKET_CONTEXT_H */
