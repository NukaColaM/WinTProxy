#ifndef WINTPROXY_CONNTRACK_H
#define WINTPROXY_CONNTRACK_H

#include <stdint.h>
#include "core/common.h"
#include "core/constants.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#endif

#define CONNTRACK_BUCKETS              WTP_CONNTRACK_BUCKETS
#define CONNTRACK_TTL_SEC              WTP_CONNTRACK_TTL_SEC
#define CONNTRACK_CLEANUP_INTERVAL_SEC WTP_CONNTRACK_CLEANUP_SEC
#define CONNTRACK_POOL_SIZE            WTP_CONNTRACK_POOL_SIZE

#ifdef __cplusplus
extern "C" {
#endif

typedef struct conntrack_entry_s {
    uint32_t key_src_ip;
    uint32_t key_dst_ip;
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t key_dst_port;
    uint16_t client_port;
    uint16_t relay_src_port;
    uint32_t orig_dst_ip;
    uint16_t orig_dst_port;
    uint32_t connect_dst_ip;
    uint16_t connect_dst_port;
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

typedef struct {
    uint32_t client_ip;
    uint16_t client_port;
    uint32_t server_ip;
    uint16_t server_port;
    uint32_t pid;
    const char *process_name;
    uint32_t if_idx;
    uint32_t sub_if_idx;
} conntrack_direct_tcp_flow_t;

typedef struct {
    uint32_t client_ip;
    uint16_t client_port;
    uint32_t server_ip;
    uint16_t server_port;
    uint16_t relay_port;
    uint16_t proposed_relay_src_port;
    uint32_t pid;
    const char *process_name;
    uint32_t if_idx;
    uint32_t sub_if_idx;
} conntrack_tcp_proxy_flow_t;

typedef struct {
    uint32_t client_ip;
    uint16_t client_port;
    uint32_t server_ip;
    uint16_t server_port;
    uint32_t pid;
    const char *process_name;
    uint32_t if_idx;
    uint32_t sub_if_idx;
} conntrack_udp_proxy_flow_t;

typedef struct {
    uint32_t client_ip;
    uint16_t client_port;
    uint32_t original_dns_ip;
    uint16_t original_dns_port;
    uint32_t redirect_ip;
    uint16_t redirect_port;
    int      loopback_redirect;
    uint32_t if_idx;
    uint32_t sub_if_idx;
} conntrack_tcp_dns_flow_t;

error_t conntrack_init(conntrack_t *ct);
void    conntrack_shutdown(conntrack_t *ct);
error_t conntrack_track_direct_tcp(conntrack_t *ct,
                                   const conntrack_direct_tcp_flow_t *flow);
error_t conntrack_track_tcp_proxy(conntrack_t *ct,
                                  const conntrack_tcp_proxy_flow_t *flow,
                                  uint16_t *relay_src_port_out);
error_t conntrack_track_udp_proxy(conntrack_t *ct,
                                  const conntrack_udp_proxy_flow_t *flow);
error_t conntrack_track_tcp_dns(conntrack_t *ct,
                                const conntrack_tcp_dns_flow_t *flow);
error_t conntrack_add(conntrack_t *ct, uint16_t src_port, uint32_t src_ip,
                      uint32_t orig_dst_ip, uint16_t orig_dst_port, uint8_t protocol,
                      uint32_t pid, const char *process_name,
                      uint32_t if_idx, uint32_t sub_if_idx);
error_t conntrack_add_key(conntrack_t *ct, uint32_t key_src_ip, uint16_t src_port,
                          uint32_t client_ip, uint32_t orig_dst_ip, uint16_t orig_dst_port,
                          uint8_t protocol, uint32_t pid, const char *process_name,
                          uint32_t if_idx, uint32_t sub_if_idx);
error_t conntrack_add_key_full(conntrack_t *ct, uint32_t key_src_ip, uint16_t key_src_port,
                               uint32_t key_dst_ip, uint16_t key_dst_port,
                               uint32_t client_ip, uint16_t client_port,
                               uint32_t orig_dst_ip, uint16_t orig_dst_port,
                               uint32_t connect_dst_ip, uint16_t connect_dst_port,
                               uint8_t protocol, uint32_t pid, const char *process_name,
                               uint32_t if_idx, uint32_t sub_if_idx,
                               uint16_t relay_src_port);
/*
 * Lookup functions return a snapshot copy of the entry under shared lock.
 * The copy is safe for immediate use but invalid after any conntrack mutation
 * (add/remove/touch) or after the next cleanup cycle (TTL expiry).
 * Callers must consume the copy synchronously — do not cache the pointer.
 */
error_t conntrack_get(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol,
                      uint32_t *orig_dst_ip, uint16_t *orig_dst_port);
error_t conntrack_get_full(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol,
                           conntrack_entry_t *out);
error_t conntrack_get_full_key(conntrack_t *ct, uint32_t src_ip, uint16_t src_port,
                               uint32_t dst_ip, uint16_t dst_port, uint8_t protocol,
                               conntrack_entry_t *out);
error_t conntrack_get_tcp_proxy_outbound(conntrack_t *ct, uint32_t client_ip,
                                         uint16_t client_port,
                                         uint32_t server_ip,
                                         uint16_t server_port,
                                         conntrack_entry_t *out);
error_t conntrack_get_tcp_proxy_return(conntrack_t *ct, uint32_t relay_src_ip,
                                       uint16_t relay_src_port,
                                       uint32_t relay_dst_ip,
                                       uint16_t relay_dst_port,
                                       conntrack_entry_t *out);
error_t conntrack_get_udp_proxy_outbound(conntrack_t *ct, uint32_t client_ip,
                                         uint16_t client_port,
                                         uint32_t server_ip,
                                         uint16_t server_port,
                                         conntrack_entry_t *out);
error_t conntrack_get_udp_proxy_return(conntrack_t *ct, uint32_t server_ip,
                                       uint16_t client_port,
                                       conntrack_entry_t *out);
error_t conntrack_get_tcp_dns_return(conntrack_t *ct, uint32_t response_src_ip,
                                     uint16_t response_src_port,
                                     uint32_t response_dst_ip,
                                     uint16_t response_dst_port,
                                     conntrack_entry_t *out);
void    conntrack_remove(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol);
void    conntrack_remove_key(conntrack_t *ct, uint32_t src_ip, uint16_t src_port,
                             uint32_t dst_ip, uint16_t dst_port, uint8_t protocol);
void    conntrack_touch(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol);
void    conntrack_touch_key(conntrack_t *ct, uint32_t src_ip, uint16_t src_port,
                            uint32_t dst_ip, uint16_t dst_port, uint8_t protocol);
/*
 * Narrow role snapshot for per-packet paths. Deliberately excludes
 * process_name and raw key fields: planners consume restored-tuple facts,
 * not entry encoding.
 */
typedef struct {
    uint32_t client_ip;
    uint32_t orig_dst_ip;
    uint16_t client_port;
    uint16_t orig_dst_port;
    uint16_t relay_src_port;   /* 0 = tracked direct (no relay leg) */
} conntrack_role_snapshot_t;

/*
 * Fused role operations: one lookup pass returns the role snapshot and
 * refreshes entry liveness. Pair liveness is owned here - a role op on one
 * side of a tracked pair keeps the entries the role depends on alive.
 * Refreshes are atomic timestamp writes under shared bucket locks.
 */
error_t conntrack_role_tcp_outbound(conntrack_t *ct, uint32_t client_ip,
                                    uint16_t client_port, uint32_t server_ip,
                                    uint16_t server_port,
                                    conntrack_role_snapshot_t *out);
error_t conntrack_role_tcp_return(conntrack_t *ct, uint32_t relay_src_ip,
                                  uint16_t relay_src_port,
                                  uint32_t relay_dst_ip,
                                  uint16_t relay_dst_port,
                                  conntrack_role_snapshot_t *out);
error_t conntrack_role_udp_outbound(conntrack_t *ct, uint32_t client_ip,
                                    uint16_t client_port, uint32_t server_ip,
                                    uint16_t server_port,
                                    conntrack_role_snapshot_t *out);
error_t conntrack_role_udp_return(conntrack_t *ct, uint32_t server_ip,
                                  uint16_t client_port,
                                  conntrack_role_snapshot_t *out);
error_t conntrack_role_tcp_dns_return(conntrack_t *ct, uint32_t response_src_ip,
                                      uint16_t response_src_port,
                                      uint32_t response_dst_ip,
                                      uint16_t response_dst_port,
                                      conntrack_role_snapshot_t *out);
void    conntrack_role_refresh_tcp_pair(conntrack_t *ct,
                                        const conntrack_entry_t *entry);

void    conntrack_snapshot_counters(conntrack_t *ct, conntrack_counters_t *out);

#ifdef __cplusplus
}
#endif

#endif
