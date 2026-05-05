#include "dns.h"
#include "log.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

#include "windivert/windivert.h"

#include <winsock2.h>

void dns_hijack_init(dns_hijack_t *dh, int enabled, uint32_t redirect_ip, uint16_t redirect_port) {
    memset(dh, 0, sizeof(*dh));
    dh->enabled = enabled;
    dh->redirect_ip = redirect_ip;
    dh->redirect_port = redirect_port;
    dh->fwd_sock = INVALID_SOCKET;
    dh->use_socket_fwd = (enabled && redirect_ip == LOOPBACK_ADDR);
    InitializeSRWLock(&dh->lock);
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

    AcquireSRWLockExclusive(&dh->lock);
    for (int i = 0; i < DNS_NAT_BUCKETS; i++) {
        dns_nat_entry_t *e = dh->buckets[i];
        while (e) {
            dns_nat_entry_t *next = e->next;
            free(e);
            e = next;
        }
        dh->buckets[i] = NULL;
    }
    ReleaseSRWLockExclusive(&dh->lock);
}

int dns_hijack_is_dns_request(uint16_t dst_port) {
    return dst_port == 53;
}

/*
 * Find or create a NAT entry for src_port.
 * Caller must hold dh->lock exclusive.
 * Returns NULL on memory allocation failure.
 */
static dns_nat_entry_t *dns_nat_ensure_entry(dns_hijack_t *dh, uint16_t src_port) {
    unsigned int idx = src_port % DNS_NAT_BUCKETS;

    dns_nat_entry_t *e = dh->buckets[idx];
    while (e) {
        if (e->src_port == src_port) return e;
        e = e->next;
    }

    e = (dns_nat_entry_t *)calloc(1, sizeof(dns_nat_entry_t));
    if (!e) return NULL;

    e->src_port = src_port;
    e->next = dh->buckets[idx];
    dh->buckets[idx] = e;
    return e;
}

/* Remove stale entries from one bucket, keeping a specific entry. Caller holds lock. */
static void dns_nat_cleanup_stale(dns_hijack_t *dh, unsigned int idx, dns_nat_entry_t *keep) {
    uint64_t now = GetTickCount64();
    dns_nat_entry_t **pp = &dh->buckets[idx];
    while (*pp) {
        if ((*pp) != keep && (now - (*pp)->timestamp) > DNS_NAT_TTL_MS) {
            dns_nat_entry_t *old = *pp;
            *pp = old->next;
            free(old);
        } else {
            pp = &(*pp)->next;
        }
    }
}

int dns_hijack_rewrite_request(dns_hijack_t *dh, uint32_t *dst_ip, uint16_t *dst_port,
                                uint16_t src_port, uint32_t original_dns_ip, uint16_t original_dns_port,
                                uint32_t client_ip, uint32_t if_idx, uint32_t sub_if_idx) {
    if (!dh->enabled) return 0;

    char orig_str[16], redir_str[16], client_str[16];
    ip_to_str(original_dns_ip, orig_str, sizeof(orig_str));
    ip_to_str(dh->redirect_ip, redir_str, sizeof(redir_str));
    ip_to_str(client_ip, client_str, sizeof(client_str));

    AcquireSRWLockExclusive(&dh->lock);

    dns_nat_entry_t *e = dns_nat_ensure_entry(dh, src_port);
    if (!e) {
        ReleaseSRWLockExclusive(&dh->lock);
        LOG_ERROR("DNS NAT: alloc failed for src_port %u", src_port);
        return -1;
    }

    e->original_dns_ip = original_dns_ip;
    e->original_dns_port = original_dns_port;
    e->client_ip = client_ip;
    e->if_idx = if_idx;
    e->sub_if_idx = sub_if_idx;
    e->timestamp = GetTickCount64();

    dns_nat_cleanup_stale(dh, src_port % DNS_NAT_BUCKETS, e);

    ReleaseSRWLockExclusive(&dh->lock);

    *dst_ip = dh->redirect_ip;
    *dst_port = dh->redirect_port;

    LOG_DEBUG("DNS hijack: port %u, %s:%u -> %s:%u",
        src_port, orig_str, original_dns_port, redir_str, dh->redirect_port);
    return 1;
}

int dns_hijack_rewrite_response(dns_hijack_t *dh, uint32_t *src_ip, uint16_t *src_port,
                                 uint16_t dst_port,
                                 uint32_t *client_ip, uint32_t *if_idx, uint32_t *sub_if_idx) {
    if (!dh->enabled) return 0;

    unsigned int idx = dst_port % DNS_NAT_BUCKETS;

    AcquireSRWLockShared(&dh->lock);

    dns_nat_entry_t *e = dh->buckets[idx];
    while (e) {
        if (e->src_port == dst_port) {
            *src_ip = e->original_dns_ip;
            *src_port = e->original_dns_port;
            if (client_ip) *client_ip = e->client_ip;
            if (if_idx) *if_idx = e->if_idx;
            if (sub_if_idx) *sub_if_idx = e->sub_if_idx;
            ReleaseSRWLockShared(&dh->lock);

            char orig_str[16], cli_str[16];
            ip_to_str(*src_ip, orig_str, sizeof(orig_str));
            if (client_ip) ip_to_str(*client_ip, cli_str, sizeof(cli_str));
            LOG_DEBUG("DNS response: restore src=%s:%u dst=%s for client port %u",
                orig_str, *src_port, client_ip ? cli_str : "?", dst_port);
            return 1;
        }
        e = e->next;
    }

    ReleaseSRWLockShared(&dh->lock);
    LOG_TRACE("DNS response: no NAT entry for client port %u", dst_port);
    return 0;
}

/*
 * Socket-based DNS forwarder for loopback targets.
 *
 * WinDivert cannot reliably inject UDP packets into the loopback stack.
 * Instead, we use a real UDP socket to forward DNS queries to the local
 * DNS server, then craft raw IP+UDP response packets and inject them
 * via WinDivert back to the original client.
 */

static DWORD WINAPI dns_fwd_thread(LPVOID param) {
    dns_hijack_t *dh = (dns_hijack_t *)param;
    uint8_t buf[2048];
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

        uint16_t resp_src_port = ntohs(from.sin_port);
        LOG_TRACE("DNS fwd: received %d bytes from port %u", n, resp_src_port);

        if (n < 2) continue;
        uint16_t txid = (buf[0] << 8) | buf[1];

        /* Find most recent NAT entry matching this DNS transaction ID */
        uint32_t orig_dns_ip = 0, client_ip = 0;
        uint16_t orig_dns_port = 0, client_src_port = 0;
        uint32_t orig_if_idx = 0, orig_sub_if_idx = 0;
        uint64_t best_ts = 0;
        int found = 0;

        AcquireSRWLockShared(&dh->lock);
        for (int i = 0; i < DNS_NAT_BUCKETS; i++) {
            dns_nat_entry_t *e = dh->buckets[i];
            while (e) {
                if (e->dns_txid == txid && e->timestamp > best_ts) {
                    orig_dns_ip = e->original_dns_ip;
                    orig_dns_port = e->original_dns_port;
                    client_ip = e->client_ip;
                    client_src_port = e->src_port;
                    orig_if_idx = e->if_idx;
                    orig_sub_if_idx = e->sub_if_idx;
                    best_ts = e->timestamp;
                    found = 1;
                }
                e = e->next;
            }
        }
        ReleaseSRWLockShared(&dh->lock);

        if (!found) {
            LOG_TRACE("DNS fwd: no NAT entry for txid 0x%04x", txid);
            continue;
        }

        char cli_str[16], orig_str[16];
        ip_to_str(client_ip, cli_str, sizeof(cli_str));
        ip_to_str(orig_dns_ip, orig_str, sizeof(orig_str));
        LOG_DEBUG("DNS fwd: response txid=0x%04x -> %s:%u (orig dns %s:%u)",
            txid, cli_str, client_src_port, orig_str, orig_dns_port);

        /* Craft raw IP + UDP + DNS response packet */
        int pkt_len = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + n;
        uint8_t pkt[sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + 2048];
        if (pkt_len > (int)sizeof(pkt)) continue;

        PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)pkt;
        PWINDIVERT_UDPHDR udp = (PWINDIVERT_UDPHDR)(pkt + sizeof(WINDIVERT_IPHDR));
        uint8_t *payload = pkt + sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR);

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
        udp->Length = htons((uint16_t)(sizeof(WINDIVERT_UDPHDR) + n));

        memcpy(payload, buf, n);

        memset(&addr, 0, sizeof(addr));
        addr.Outbound = 0;
        addr.Loopback = 0;
        addr.Network.IfIdx = orig_if_idx;
        addr.Network.SubIfIdx = orig_sub_if_idx;

        WinDivertHelperCalcChecksums(pkt, pkt_len, &addr, 0);

        BOOL sent = WinDivertSend(dh->divert_handle, pkt, pkt_len, NULL, &addr);
        if (!sent) {
            LOG_WARN("DNS fwd: WinDivertSend failed: err=%lu", GetLastError());
        } else {
            LOG_DEBUG("DNS fwd: injected response to %s:%u IfIdx=%lu",
                cli_str, client_src_port, (unsigned long)orig_if_idx);
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

    /* Set receive timeout so the thread can check fwd_running periodically */
    DWORD timeout = 1000;
    setsockopt(dh->fwd_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

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

    struct sockaddr_in local;
    int local_len = sizeof(local);
    getsockname(dh->fwd_sock, (struct sockaddr *)&local, &local_len);
    LOG_INFO("DNS forwarder socket bound to 127.0.0.1:%u", ntohs(local.sin_port));

    dh->fwd_running = 1;
    dh->fwd_thread = CreateThread(NULL, 0, dns_fwd_thread, dh, 0, NULL);
    if (!dh->fwd_thread) {
        LOG_ERROR("DNS fwd: CreateThread failed");
        closesocket(dh->fwd_sock);
        dh->fwd_sock = INVALID_SOCKET;
        return ERR_GENERIC;
    }

    return ERR_OK;
}

error_t dns_hijack_forward_query(dns_hijack_t *dh, const uint8_t *dns_payload, int dns_len,
                                 uint16_t src_port, uint32_t original_dns_ip, uint16_t original_dns_port,
                                 uint32_t client_ip, uint32_t if_idx, uint32_t sub_if_idx) {
    if (dh->fwd_sock == INVALID_SOCKET || dns_len < 2) return ERR_PARAM;

    uint16_t txid = (dns_payload[0] << 8) | dns_payload[1];

    AcquireSRWLockExclusive(&dh->lock);
    dns_nat_entry_t *e = dns_nat_ensure_entry(dh, src_port);
    if (!e) {
        ReleaseSRWLockExclusive(&dh->lock);
        return ERR_MEMORY;
    }
    e->dns_txid = txid;
    e->original_dns_ip = original_dns_ip;
    e->original_dns_port = original_dns_port;
    e->client_ip = client_ip;
    e->if_idx = if_idx;
    e->sub_if_idx = sub_if_idx;
    e->timestamp = GetTickCount64();
    ReleaseSRWLockExclusive(&dh->lock);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dh->redirect_ip;
    dest.sin_port = htons(dh->redirect_port);

    int sent = sendto(dh->fwd_sock, (const char *)dns_payload, dns_len, 0,
                      (struct sockaddr *)&dest, sizeof(dest));
    if (sent == SOCKET_ERROR) {
        LOG_WARN("DNS fwd: sendto failed: %d", WSAGetLastError());
        return ERR_NETWORK;
    }

    LOG_DEBUG("DNS fwd: sent %d bytes to 127.0.0.1:%u (txid=0x%04x, client port %u)",
        sent, dh->redirect_port, txid, src_port);
    return ERR_OK;
}
