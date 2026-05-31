/*
 * Network header structures for manual packet parsing.
 * Adapted from Proxifyre iphlp.h — BSD-style definitions, C-compatible.
 * Network header types for manual packet parsing (Ethernet → IPv4 → TCP/UDP).
 */
#ifndef WINTPROXY_NET_HEADERS_H
#define WINTPROXY_NET_HEADERS_H

#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#endif

/* === Ethernet === */

#define ETHER_ADDR_LEN  6
#define ETHER_HDR_LEN   14
#define ETH_P_IP        0x0800

typedef struct ether_header {
    uint8_t  h_dest[ETHER_ADDR_LEN];
    uint8_t  h_source[ETHER_ADDR_LEN];
    uint16_t h_proto;
} ether_header_t;

typedef ether_header_t *ether_header_ptr;

/* === IPv4 === */

typedef struct iphdr {
    uint8_t  ip_hl : 4,
             ip_v  : 4;
    uint8_t  ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t  ip_ttl;
    uint8_t  ip_p;
    uint16_t ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
} iphdr_t;

typedef iphdr_t *iphdr_ptr;

/* === TCP === */

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

typedef struct tcphdr {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t  th_x2 : 4,
             th_off : 4;
    uint8_t  th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
} tcphdr_t;

typedef tcphdr_t *tcphdr_ptr;

/* === UDP === */

typedef struct udphdr {
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_ulen;
    uint16_t uh_sum;
} udphdr_t;

typedef udphdr_t *udphdr_ptr;

#endif /* WINTPROXY_NET_HEADERS_H */
