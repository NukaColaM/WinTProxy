#ifndef WINTPROXY_DNS_H
#define WINTPROXY_DNS_H

#include <stdint.h>
#include "common.h"
#include "constants.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#endif

#define DNS_NAT_BUCKETS WTP_DNS_NAT_BUCKETS
#define DNS_NAT_TTL_MS  WTP_DNS_NAT_TTL_MS

typedef struct dns_nat_entry_s {
    uint16_t src_port;
    uint16_t dns_txid;
    uint16_t fwd_src_port;
    uint16_t fwd_txid;
    uint32_t original_dns_ip;
    uint16_t original_dns_port;
    uint32_t client_ip;
    uint32_t if_idx;
    uint32_t sub_if_idx;
    uint64_t timestamp;
    struct dns_nat_entry_s *next;
} dns_nat_entry_t;

typedef struct dns_hijack_s dns_hijack_t;

struct dns_hijack_s {
    int              enabled;
    uint32_t         redirect_ip;
    uint16_t         redirect_port;
    int              use_socket_fwd;
    SOCKET           fwd_sock;
    uint16_t         fwd_src_port;
    uint16_t         next_fwd_txid;
    HANDLE           fwd_thread;
    volatile int     fwd_running;
    void            *divert_handle;
    dns_nat_entry_t *buckets[DNS_NAT_BUCKETS];
    SRWLOCK          lock;
};

void dns_hijack_init(dns_hijack_t *dh, int enabled, uint32_t redirect_ip, uint16_t redirect_port);
void dns_hijack_shutdown(dns_hijack_t *dh);

int dns_hijack_is_dns_request(uint16_t dst_port);

int dns_hijack_rewrite_request(dns_hijack_t *dh, uint32_t *dst_ip, uint16_t *dst_port,
                                uint16_t src_port, uint16_t dns_txid,
                                uint32_t original_dns_ip, uint16_t original_dns_port,
                                uint32_t client_ip, uint32_t if_idx, uint32_t sub_if_idx);

int dns_hijack_rewrite_response(dns_hijack_t *dh, uint32_t *src_ip, uint16_t *src_port,
                                 uint16_t dst_port, uint16_t dns_txid,
                                 uint32_t *client_ip, uint32_t *if_idx, uint32_t *sub_if_idx);

error_t dns_hijack_start_forwarder(dns_hijack_t *dh, void *divert_handle);
error_t dns_hijack_forward_query(dns_hijack_t *dh, const uint8_t *dns_payload, int dns_len,
                                 uint16_t src_port, uint32_t original_dns_ip, uint16_t original_dns_port,
                                 uint32_t client_ip, uint32_t if_idx, uint32_t sub_if_idx);

#endif
