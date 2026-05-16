#ifndef WINTPROXY_PACKET_CONTEXT_H
#define WINTPROXY_PACKET_CONTEXT_H

#include <stdint.h>
#include <winsock2.h>
#include "windivert/windivert.h"

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
    const uint8_t     *payload_data;
    UINT               payload_len;
    int                payload_valid;
    uint16_t           dns_txid;
    int                dns_txid_valid;
} packet_ctx_t;

int packet_parse(packet_ctx_t *ctx, uint8_t *packet, UINT packet_len);
int packet_payload(packet_ctx_t *ctx, const uint8_t **payload, UINT *payload_len);
int packet_dns_txid(packet_ctx_t *ctx, uint16_t *txid);
int packet_dns_query_summary(packet_ctx_t *ctx, int tcp_framed, packet_dns_query_summary_t *summary);
int packet_clamp_tcp_mss(packet_ctx_t *ctx, uint16_t max_mss);
void packet_recalculate_checksums(packet_ctx_t *ctx, WINDIVERT_ADDRESS *addr);

#ifdef __cplusplus
}
#endif

#endif
