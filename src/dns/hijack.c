#include "dns/hijack.h"
#include "app/log.h"
#include "core/util.h"
#include <stdlib.h>
#include <string.h>

#include "windivert/windivert.h"

#include <winsock2.h>

static unsigned int dns_nat_hash_client(uint16_t src_port, uint16_t dns_txid) {
    return (((unsigned int)src_port * 131U) ^ (unsigned int)dns_txid) % DNS_NAT_BUCKETS;
}

static unsigned int dns_nat_hash_forward(uint16_t fwd_src_port, uint16_t fwd_txid) {
    return (((unsigned int)fwd_src_port * 257U) ^ (unsigned int)fwd_txid) % DNS_NAT_BUCKETS;
}

static dns_nat_entry_t *dns_nat_pool_alloc(dns_hijack_t *dh) {
    dns_nat_entry_t *e;
    e = dh->free_list;
    if (e) {
        dh->free_list = e->next;
        memset(e, 0, sizeof(*e));
    }
    return e;
}

static void dns_nat_pool_free(dns_hijack_t *dh, dns_nat_entry_t *e) {
    memset(e, 0, sizeof(*e));
    e->next = dh->free_list;
    dh->free_list = e;
}

static dns_nat_entry_t *dns_nat_find_client(dns_hijack_t *dh, uint16_t src_port,
                                            uint16_t dns_txid, unsigned int idx) {
    dns_nat_entry_t *e = dh->buckets[idx];
    while (e) {
        if (e->src_port == src_port && e->dns_txid == dns_txid && e->fwd_txid == 0) {
            return e;
        }
        e = e->next;
    }
    return NULL;
}

static dns_nat_entry_t *dns_nat_find_forward(dns_hijack_t *dh, uint16_t fwd_src_port,
                                             uint16_t fwd_txid, unsigned int idx) {
    dns_nat_entry_t *e = dh->buckets[idx];
    while (e) {
        if (e->fwd_src_port == fwd_src_port && e->fwd_txid == fwd_txid) {
            return e;
        }
        e = e->next;
    }
    return NULL;
}

static dns_nat_entry_t *dns_nat_upsert_client(dns_hijack_t *dh, uint16_t src_port,
                                              uint16_t dns_txid, unsigned int idx) {
    dns_nat_entry_t *e = dns_nat_find_client(dh, src_port, dns_txid, idx);
    if (e) return e;

    e = dns_nat_pool_alloc(dh);
    if (!e) return NULL;

    e->src_port = src_port;
    e->dns_txid = dns_txid;
    e->next = dh->buckets[idx];
    dh->buckets[idx] = e;
    return e;
}

static dns_nat_entry_t *dns_nat_insert_forward(dns_hijack_t *dh, uint16_t src_port,
                                               uint16_t dns_txid, uint16_t fwd_src_port,
                                               uint16_t fwd_txid, unsigned int idx) {
    dns_nat_entry_t *e = dns_nat_pool_alloc(dh);
    if (!e) return NULL;

    e->src_port = src_port;
    e->dns_txid = dns_txid;
    e->fwd_src_port = fwd_src_port;
    e->fwd_txid = fwd_txid;
    e->next = dh->buckets[idx];
    dh->buckets[idx] = e;
    return e;
}

static void dns_nat_remove_entry(dns_hijack_t *dh, unsigned int idx, dns_nat_entry_t *entry) {
    dns_nat_entry_t **pp = &dh->buckets[idx];
    while (*pp) {
        if (*pp == entry) {
            *pp = entry->next;
            dns_nat_pool_free(dh, entry);
            return;
        }
        pp = &(*pp)->next;
    }
}

static void dns_nat_cleanup_stale_bucket(dns_hijack_t *dh, unsigned int idx,
                                         dns_nat_entry_t *keep) {
    uint64_t now = GetTickCount64();
    dns_nat_entry_t **pp = &dh->buckets[idx];
    while (*pp) {
        if ((*pp) != keep && (now - (*pp)->timestamp) > DNS_NAT_TTL_MS) {
            dns_nat_entry_t *old = *pp;
            *pp = old->next;
            dns_nat_pool_free(dh, old);
        } else {
            pp = &(*pp)->next;
        }
    }
}

static void dns_nat_cleanup_all(dns_hijack_t *dh) {
    for (int i = 0; i < DNS_NAT_BUCKETS; i++) {
        dns_nat_cleanup_stale_bucket(dh, (unsigned int)i, NULL);
    }
}

static uint16_t dns_nat_alloc_forward_txid(dns_hijack_t *dh, uint16_t fwd_src_port,
                                           unsigned int *idx_out) {
    uint16_t first;
    uint16_t candidate;

    if (dh->next_fwd_txid == 0) {
        dh->next_fwd_txid = (uint16_t)GetTickCount64();
        if (dh->next_fwd_txid == 0) dh->next_fwd_txid = 1;
    }

    first = dh->next_fwd_txid;
    candidate = first;
    do {
        unsigned int idx = dns_nat_hash_forward(fwd_src_port, candidate);
        if (!dns_nat_find_forward(dh, fwd_src_port, candidate, idx)) {
            *idx_out = idx;
            dh->next_fwd_txid = (uint16_t)(candidate + 1U);
            if (dh->next_fwd_txid == 0) dh->next_fwd_txid = 1;
            return candidate;
        }

        candidate = (uint16_t)(candidate + 1U);
        if (candidate == 0) candidate = 1;
    } while (candidate != first);

    *idx_out = 0;
    return 0;
}

static void dns_nat_fill_entry(dns_nat_entry_t *e, uint32_t original_dns_ip,
                               uint16_t original_dns_port, uint32_t client_ip,
                               uint32_t if_idx, uint32_t sub_if_idx) {
    e->original_dns_ip = original_dns_ip;
    e->original_dns_port = original_dns_port;
    e->client_ip = client_ip;
    e->if_idx = if_idx;
    e->sub_if_idx = sub_if_idx;
    e->timestamp = GetTickCount64();
}

error_t dns_hijack_init(dns_hijack_t *dh, int enabled, uint32_t redirect_ip, uint16_t redirect_port) {
    memset(dh, 0, sizeof(*dh));
    dh->enabled = enabled;
    dh->redirect_ip = redirect_ip;
    dh->redirect_port = redirect_port;
    dh->fwd_sock = INVALID_SOCKET;
    dh->use_socket_fwd = (enabled && redirect_ip == LOOPBACK_ADDR);
    dh->next_fwd_txid = (uint16_t)GetTickCount64();
    if (dh->next_fwd_txid == 0) dh->next_fwd_txid = 1;
    InitializeSRWLock(&dh->lock);
    dh->free_list = NULL;
    dh->bucket_count = DNS_NAT_BUCKETS;
    dh->pool_size = DNS_NAT_POOL_SIZE;
    dh->buckets = (dns_nat_entry_t **)calloc(dh->bucket_count, sizeof(dh->buckets[0]));
    dh->pool = (dns_nat_entry_t *)calloc(dh->pool_size, sizeof(dh->pool[0]));
    if (!dh->buckets || !dh->pool) {
        free(dh->buckets);
        free(dh->pool);
        memset(dh, 0, sizeof(*dh));
        return ERR_MEMORY;
    }
    for (size_t i = 0; i < dh->pool_size; i++) {
        dh->pool[i].next = dh->free_list;
        dh->free_list = &dh->pool[i];
    }
    return ERR_OK;
}

void dns_hijack_shutdown(dns_hijack_t *dh) {
    dh->fwd_running = 0;
    if (dh->fwd_sock != INVALID_SOCKET) {
        closesocket(dh->fwd_sock);
        dh->fwd_sock = INVALID_SOCKET;
    }
    if (dh->fwd_thread) {
        WaitForSingleObject(dh->fwd_thread, 3000);
        CloseHandle(dh->fwd_thread);
        dh->fwd_thread = NULL;
    }
    dh->fwd_src_port = 0;

    AcquireSRWLockExclusive(&dh->lock);
    for (size_t i = 0; i < dh->bucket_count; i++) {
        dns_nat_entry_t *e = dh->buckets[i];
        while (e) {
            dns_nat_entry_t *next = e->next;
            dns_nat_pool_free(dh, e);
            e = next;
        }
        dh->buckets[i] = NULL;
    }
    ReleaseSRWLockExclusive(&dh->lock);
    free(dh->buckets);
    free(dh->pool);
    dh->buckets = NULL;
    dh->pool = NULL;
    dh->free_list = NULL;
    dh->bucket_count = 0;
    dh->pool_size = 0;
}

int dns_hijack_is_dns_request(uint16_t dst_port) {
    return dst_port == 53;
}

int dns_hijack_rewrite_request(dns_hijack_t *dh, uint32_t *dst_ip, uint16_t *dst_port,
                                uint16_t src_port, uint16_t dns_txid,
                                uint32_t original_dns_ip, uint16_t original_dns_port,
                                uint32_t client_ip, uint32_t if_idx, uint32_t sub_if_idx) {
    unsigned int idx;
    dns_nat_entry_t *e;

    if (!dh->enabled) return 0;

    idx = dns_nat_hash_client(src_port, dns_txid);
    AcquireSRWLockExclusive(&dh->lock);

    e = dns_nat_upsert_client(dh, src_port, dns_txid, idx);
    if (!e) {
        ReleaseSRWLockExclusive(&dh->lock);
        LOG_ERROR("DNS NAT: alloc failed for src_port %u txid 0x%04x", src_port, dns_txid);
        return -1;
    }

    dns_nat_fill_entry(e, original_dns_ip, original_dns_port, client_ip, if_idx, sub_if_idx);
    dns_nat_cleanup_stale_bucket(dh, idx, e);

    ReleaseSRWLockExclusive(&dh->lock);

    *dst_ip = dh->redirect_ip;
    *dst_port = dh->redirect_port;

    {
        char orig_str[16], redir_str[16];
        ip_to_str(original_dns_ip, orig_str, sizeof(orig_str));
        ip_to_str(dh->redirect_ip, redir_str, sizeof(redir_str));
        LOG_PACKET("DNS hijack: port %u txid=0x%04x, %s:%u -> %s:%u",
            src_port, dns_txid, orig_str, original_dns_port, redir_str, dh->redirect_port);
    }

    return 1;
}

int dns_hijack_rewrite_response(dns_hijack_t *dh, uint32_t *src_ip, uint16_t *src_port,
                                 uint16_t dst_port, uint16_t dns_txid,
                                 uint32_t *client_ip, uint32_t *if_idx, uint32_t *sub_if_idx) {
    unsigned int idx;
    dns_nat_entry_t *e;
    uint64_t now;

    if (!dh->enabled) return 0;

    idx = dns_nat_hash_client(dst_port, dns_txid);
    AcquireSRWLockExclusive(&dh->lock);

    e = dns_nat_find_client(dh, dst_port, dns_txid, idx);
    if (!e) {
        ReleaseSRWLockExclusive(&dh->lock);
        LOG_PACKET("DNS response: no NAT entry for client port %u txid=0x%04x", dst_port, dns_txid);
        return 0;
    }

    now = GetTickCount64();
    if ((now - e->timestamp) > DNS_NAT_TTL_MS) {
        dns_nat_remove_entry(dh, idx, e);
        ReleaseSRWLockExclusive(&dh->lock);
        LOG_PACKET("DNS response: stale NAT entry for client port %u txid=0x%04x", dst_port, dns_txid);
        return 0;
    }

    *src_ip = e->original_dns_ip;
    *src_port = e->original_dns_port;
    if (client_ip) *client_ip = e->client_ip;
    if (if_idx) *if_idx = e->if_idx;
    if (sub_if_idx) *sub_if_idx = e->sub_if_idx;
    dns_nat_remove_entry(dh, idx, e);
    ReleaseSRWLockExclusive(&dh->lock);

    {
        char orig_str[16], cli_str[16];
        ip_to_str(*src_ip, orig_str, sizeof(orig_str));
        if (client_ip) ip_to_str(*client_ip, cli_str, sizeof(cli_str));
        LOG_PACKET("DNS response: restore src=%s:%u dst=%s for client port %u txid=0x%04x",
            orig_str, *src_port, client_ip ? cli_str : "?", dst_port, dns_txid);
    }
    return 1;
}

static DWORD WINAPI dns_fwd_thread(LPVOID param) {
    dns_hijack_t *dh = (dns_hijack_t *)param;
    uint8_t buf[WTP_DNS_FORWARD_BUFFER_SIZE];
    WINDIVERT_ADDRESS addr;

    while (dh->fwd_running) {
        struct sockaddr_in from;
        int from_len = sizeof(from);
        int n = recvfrom(dh->fwd_sock, (char *)buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &from_len);
        if (n <= 0) {
            if (!dh->fwd_running) break;
            continue;
        }

        if (n < 2) continue;

        {
            uint16_t fwd_txid = (uint16_t)(((uint16_t)buf[0] << 8) | (uint16_t)buf[1]);
            uint32_t orig_dns_ip = 0;
            uint32_t client_ip = 0;
            uint16_t orig_dns_port = 0;
            uint16_t client_src_port = 0;
            uint16_t original_txid = 0;
            uint32_t orig_if_idx = 0;
            uint32_t orig_sub_if_idx = 0;
            unsigned int idx = dns_nat_hash_forward(dh->fwd_src_port, fwd_txid);
            dns_nat_entry_t *e;
            int found = 0;

            AcquireSRWLockExclusive(&dh->lock);
            e = dns_nat_find_forward(dh, dh->fwd_src_port, fwd_txid, idx);
            if (e && (GetTickCount64() - e->timestamp) <= DNS_NAT_TTL_MS) {
                orig_dns_ip = e->original_dns_ip;
                orig_dns_port = e->original_dns_port;
                client_ip = e->client_ip;
                client_src_port = e->src_port;
                original_txid = e->dns_txid;
                orig_if_idx = e->if_idx;
                orig_sub_if_idx = e->sub_if_idx;
                dns_nat_remove_entry(dh, idx, e);
                found = 1;
            } else if (e) {
                dns_nat_remove_entry(dh, idx, e);
            }
            ReleaseSRWLockExclusive(&dh->lock);

            if (!found) {
                LOG_PACKET("DNS fwd: no NAT entry for forwarded txid 0x%04x", fwd_txid);
                continue;
            }

            buf[0] = (uint8_t)(original_txid >> 8);
            buf[1] = (uint8_t)(original_txid & 0xFF);

            {
                int pkt_len = (int)(sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + (size_t)n);
                uint8_t pkt[sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + WTP_DNS_FORWARD_BUFFER_SIZE];
                PWINDIVERT_IPHDR ip;
                PWINDIVERT_UDPHDR udp;
                uint8_t *payload;
                char cli_str[16], orig_str[16];

                if (pkt_len > (int)sizeof(pkt)) continue;

                ip = (PWINDIVERT_IPHDR)pkt;
                udp = (PWINDIVERT_UDPHDR)(pkt + sizeof(WINDIVERT_IPHDR));
                payload = pkt + sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR);

                memset(ip, 0, sizeof(WINDIVERT_IPHDR));
                ip->Version = 4;
                ip->HdrLength = sizeof(WINDIVERT_IPHDR) / 4;
                ip->Length = htons((uint16_t)pkt_len);
                ip->TTL = 64;
                ip->Protocol = 17;
                ip->SrcAddr = orig_dns_ip;
                ip->DstAddr = client_ip;

                memset(udp, 0, sizeof(WINDIVERT_UDPHDR));
                udp->SrcPort = htons(orig_dns_port);
                udp->DstPort = htons(client_src_port);
                udp->Length = htons((uint16_t)(sizeof(WINDIVERT_UDPHDR) + (size_t)n));

                memcpy(payload, buf, (size_t)n);

                memset(&addr, 0, sizeof(addr));
                addr.Outbound = 0;
                addr.Loopback = 0;
                addr.Network.IfIdx = orig_if_idx;
                addr.Network.SubIfIdx = orig_sub_if_idx;

                WinDivertHelperCalcChecksums(pkt, (UINT)pkt_len, &addr, 0);

                ip_to_str(client_ip, cli_str, sizeof(cli_str));
                ip_to_str(orig_dns_ip, orig_str, sizeof(orig_str));
                if (!WinDivertSend(dh->divert_handle, pkt, (UINT)pkt_len, NULL, &addr)) {
                    LOG_WARN("DNS fwd: WinDivertSend failed: err=%lu", GetLastError());
                } else {
                    LOG_PACKET("DNS fwd: txid=0x%04x restored from 0x%04x to %s:%u (orig dns %s:%u)",
                        original_txid, fwd_txid, cli_str, client_src_port, orig_str, orig_dns_port);
                }
            }
        }
    }

    return 0;
}

error_t dns_hijack_start_forwarder(dns_hijack_t *dh, void *divert_handle) {
    if (!dh->use_socket_fwd) return ERR_OK;

    dh->divert_handle = divert_handle;

    dh->fwd_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dh->fwd_sock == INVALID_SOCKET) {
        LOG_ERROR("DNS fwd: socket() failed: %d", WSAGetLastError());
        return ERR_NETWORK;
    }

    {
        DWORD timeout = 1000;
        setsockopt(dh->fwd_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    }

    {
        struct sockaddr_in bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind_addr.sin_port = 0;

        if (bind(dh->fwd_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
            LOG_ERROR("DNS fwd: bind() failed: %d", WSAGetLastError());
            closesocket(dh->fwd_sock);
            dh->fwd_sock = INVALID_SOCKET;
            return ERR_NETWORK;
        }
    }

    {
        struct sockaddr_in local;
        int local_len = sizeof(local);
        if (getsockname(dh->fwd_sock, (struct sockaddr *)&local, &local_len) == SOCKET_ERROR) {
            LOG_ERROR("DNS fwd: getsockname() failed: %d", WSAGetLastError());
            closesocket(dh->fwd_sock);
            dh->fwd_sock = INVALID_SOCKET;
            return ERR_NETWORK;
        }
        dh->fwd_src_port = ntohs(local.sin_port);
        LOG_INFO("DNS forwarder socket bound to 127.0.0.1:%u", dh->fwd_src_port);
    }

    dh->fwd_running = 1;
    dh->fwd_thread = CreateThread(NULL, 0, dns_fwd_thread, dh, 0, NULL);
    if (!dh->fwd_thread) {
        LOG_ERROR("DNS fwd: CreateThread failed");
        dh->fwd_running = 0;
        closesocket(dh->fwd_sock);
        dh->fwd_sock = INVALID_SOCKET;
        dh->fwd_src_port = 0;
        return ERR_GENERIC;
    }

    return ERR_OK;
}

error_t dns_hijack_forward_query(dns_hijack_t *dh, const uint8_t *dns_payload, int dns_len,
                                 uint16_t src_port, uint32_t original_dns_ip, uint16_t original_dns_port,
                                 uint32_t client_ip, uint32_t if_idx, uint32_t sub_if_idx) {
    uint8_t fwd_payload[WTP_DNS_FORWARD_BUFFER_SIZE];
    uint16_t original_txid;
    uint16_t fwd_txid;
    unsigned int idx;
    dns_nat_entry_t *e;
    struct sockaddr_in dest;
    int sent;

    if (dh->fwd_sock == INVALID_SOCKET || dns_len < 2 ||
        dns_len > (int)sizeof(fwd_payload) || dh->fwd_src_port == 0) {
        return ERR_PARAM;
    }

    memcpy(fwd_payload, dns_payload, (size_t)dns_len);
    original_txid = (uint16_t)(((uint16_t)fwd_payload[0] << 8) | (uint16_t)fwd_payload[1]);

    AcquireSRWLockExclusive(&dh->lock);
    dns_nat_cleanup_all(dh);

    fwd_txid = dns_nat_alloc_forward_txid(dh, dh->fwd_src_port, &idx);
    if (fwd_txid == 0) {
        ReleaseSRWLockExclusive(&dh->lock);
        return ERR_BUSY;
    }

    e = dns_nat_insert_forward(dh, src_port, original_txid, dh->fwd_src_port, fwd_txid, idx);
    if (!e) {
        ReleaseSRWLockExclusive(&dh->lock);
        return ERR_MEMORY;
    }
    dns_nat_fill_entry(e, original_dns_ip, original_dns_port, client_ip, if_idx, sub_if_idx);
    ReleaseSRWLockExclusive(&dh->lock);

    fwd_payload[0] = (uint8_t)(fwd_txid >> 8);
    fwd_payload[1] = (uint8_t)(fwd_txid & 0xFF);

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dh->redirect_ip;
    dest.sin_port = htons(dh->redirect_port);

    sent = sendto(dh->fwd_sock, (const char *)fwd_payload, dns_len, 0,
                  (struct sockaddr *)&dest, sizeof(dest));
        if (sent == SOCKET_ERROR) {
            LOG_WARN("DNS fwd: sendto failed: %d", WSAGetLastError());
            AcquireSRWLockExclusive(&dh->lock);
            dns_nat_remove_entry(dh, idx, e);
            ReleaseSRWLockExclusive(&dh->lock);
        return ERR_NETWORK;
    }

    LOG_PACKET("DNS fwd: sent %d bytes to 127.0.0.1:%u (client port %u txid 0x%04x -> 0x%04x)",
        sent, dh->redirect_port, src_port, original_txid, fwd_txid);
    return ERR_OK;
}
