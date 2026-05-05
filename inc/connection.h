#ifndef WINTPROXY_CONNECTION_H
#define WINTPROXY_CONNECTION_H

#include <stdint.h>
#include "common.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#endif

#define CONNTRACK_BUCKETS 1024
#define CONNTRACK_TTL_SEC 60
#define CONNTRACK_CLEANUP_INTERVAL_SEC 30

typedef struct conntrack_entry_s {
    uint16_t src_port;
    uint32_t src_ip;
    uint32_t orig_dst_ip;
    uint16_t orig_dst_port;
    uint8_t  protocol;
    uint32_t pid;
    char     process_name[256];
    uint64_t timestamp;
    uint32_t if_idx;
    uint32_t sub_if_idx;
    struct conntrack_entry_s *next;
} conntrack_entry_t;

typedef struct {
    conntrack_entry_t *buckets[CONNTRACK_BUCKETS];
    SRWLOCK            locks[CONNTRACK_BUCKETS];
    volatile int       running;
    HANDLE             cleanup_thread;
} conntrack_t;

error_t conntrack_init(conntrack_t *ct);
void    conntrack_shutdown(conntrack_t *ct);
error_t conntrack_add(conntrack_t *ct, uint16_t src_port, uint32_t src_ip,
                      uint32_t orig_dst_ip, uint16_t orig_dst_port, uint8_t protocol,
                      uint32_t pid, const char *process_name,
                      uint32_t if_idx, uint32_t sub_if_idx);
error_t conntrack_get(conntrack_t *ct, uint16_t src_port, uint8_t protocol,
                      uint32_t *orig_dst_ip, uint16_t *orig_dst_port);
error_t conntrack_get_full(conntrack_t *ct, uint16_t src_port, uint8_t protocol,
                           conntrack_entry_t *out);
void    conntrack_remove(conntrack_t *ct, uint16_t src_port, uint8_t protocol);
void    conntrack_touch(conntrack_t *ct, uint16_t src_port, uint8_t protocol);

#endif
