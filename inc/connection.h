#ifndef WINTPROXY_CONNECTION_H
#define WINTPROXY_CONNECTION_H

#include <stdint.h>
#include "common.h"
#include "constants.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#endif

#define CONNTRACK_BUCKETS              WTP_CONNTRACK_BUCKETS
#define CONNTRACK_TTL_SEC              WTP_CONNTRACK_TTL_SEC
#define CONNTRACK_CLEANUP_INTERVAL_SEC WTP_CONNTRACK_CLEANUP_SEC
#define CONNTRACK_POOL_SIZE            WTP_CONNTRACK_POOL_SIZE

typedef struct conntrack_entry_s {
    uint32_t key_src_ip;
    uint32_t src_ip;
    uint16_t src_port;
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
    volatile LONG64 adds;
    volatile LONG64 updates;
    volatile LONG64 removes;
    volatile LONG64 misses;
    volatile LONG64 pool_exhausted;
    volatile LONG64 stale_cleanups;
} conntrack_counters_t;

typedef struct {
    conntrack_entry_t **buckets;
    conntrack_entry_t  *pool;
    conntrack_entry_t *free_list;
    SRWLOCK           *locks;
    size_t             bucket_count;
    size_t             pool_size;
    SRWLOCK            pool_lock;
    conntrack_counters_t counters;
    volatile int       running;
    HANDLE             cleanup_thread;
    HANDLE             stop_event;
} conntrack_t;

error_t conntrack_init(conntrack_t *ct);
void    conntrack_shutdown(conntrack_t *ct);
error_t conntrack_add(conntrack_t *ct, uint16_t src_port, uint32_t src_ip,
                      uint32_t orig_dst_ip, uint16_t orig_dst_port, uint8_t protocol,
                      uint32_t pid, const char *process_name,
                      uint32_t if_idx, uint32_t sub_if_idx);
error_t conntrack_add_key(conntrack_t *ct, uint32_t key_src_ip, uint16_t src_port,
                          uint32_t client_ip, uint32_t orig_dst_ip, uint16_t orig_dst_port,
                          uint8_t protocol, uint32_t pid, const char *process_name,
                          uint32_t if_idx, uint32_t sub_if_idx);
error_t conntrack_get(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol,
                      uint32_t *orig_dst_ip, uint16_t *orig_dst_port);
error_t conntrack_get_full(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol,
                           conntrack_entry_t *out);
void    conntrack_remove(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol);
void    conntrack_touch(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol);
void    conntrack_snapshot_counters(conntrack_t *ct, conntrack_counters_t *out);

#endif
