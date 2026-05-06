#ifndef WINTPROXY_PROCESS_H
#define WINTPROXY_PROCESS_H

#include <stdint.h>
#include <stddef.h>
#include "common.h"
#include "constants.h"

#ifdef _WIN32
#include <windows.h>
#endif

#define PROC_FLOW_BUCKETS       WTP_PROC_FLOW_BUCKETS
#define PROC_FLOW_POOL_SIZE     WTP_PROC_FLOW_POOL_SIZE
#define PROC_PID_BUCKETS        WTP_PROC_PID_BUCKETS
#define PROC_PID_POOL_SIZE      WTP_PROC_PID_POOL_SIZE
#define PROC_INDEX_REFRESH_MS   WTP_PROC_INDEX_REFRESH_MS
#define PROC_MISS_REFRESH_MIN_MS WTP_PROC_MISS_REFRESH_MIN_MS
#define PROC_CACHE_TTL_MS       WTP_PROC_CACHE_TTL_MS

typedef struct proc_flow_entry_s {
    uint32_t ip;
    uint16_t port;
    uint8_t  protocol;
    uint32_t pid;
    char     name[256];
    struct proc_flow_entry_s *next;
} proc_flow_entry_t;

typedef struct {
    uint32_t ip;
    uint16_t port;
    uint8_t  protocol;
    uint32_t pid;
    char     name[256];
} proc_flow_record_t;

typedef struct proc_pid_entry_s {
    uint32_t pid;
    char     name[256];
    uint64_t timestamp;
    struct proc_pid_entry_s *next;
} proc_pid_entry_t;

typedef struct {
    volatile LONG64 flow_hits;
    volatile LONG64 wildcard_hits;
    volatile LONG64 misses;
    volatile LONG64 refreshes;
    volatile LONG64 flow_events;
    volatile LONG64 pid_hits;
    volatile LONG64 pid_misses;
    volatile LONG64 pool_exhausted;
} proc_lookup_counters_t;

typedef struct {
    proc_flow_entry_t **flow_buckets;
    proc_flow_entry_t  *flow_pool;
    size_t             flow_used;
    size_t             flow_bucket_count;
    size_t             flow_pool_size;
    SRWLOCK            flow_lock;

    proc_pid_entry_t  **pid_buckets;
    proc_pid_entry_t   *pid_pool;
    size_t             pid_used;
    size_t             pid_bucket_count;
    size_t             pid_pool_size;
    SRWLOCK            pid_lock;

    proc_flow_record_t *scratch;
    size_t             indexed_flows;
    uint64_t           last_refresh_ms;
    CRITICAL_SECTION   refresh_lock;
    HANDLE             refresh_event;
    uint32_t           self_pid;
    proc_lookup_counters_t counters;
    volatile int       running;
    HANDLE             refresh_thread;
    HANDLE             flow_handle;
    HANDLE             flow_thread;
} proc_lookup_t;

error_t proc_lookup_init(proc_lookup_t *pl);
void    proc_lookup_shutdown(proc_lookup_t *pl);

uint32_t proc_lookup_tcp(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port, char *name_out, int name_len);
uint32_t proc_lookup_udp(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port, char *name_out, int name_len);
uint32_t proc_lookup_tcp_retry(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port, char *name_out, int name_len);
uint32_t proc_lookup_udp_retry(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port, char *name_out, int name_len);

int proc_is_self(proc_lookup_t *pl, uint32_t pid);
void proc_lookup_snapshot_counters(proc_lookup_t *pl, proc_lookup_counters_t *out);

#endif
