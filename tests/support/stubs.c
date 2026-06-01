#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "app/log.h"
#include "conntrack/conntrack.h"
#include "core/common.h"
#include "flow/action.h"
#include "ndisapi/adapter.h"
#include "process/lookup.h"

int g_test_adapter_send_count = 0;
int g_test_mstcp_send_count = 0;
int g_test_drop_count = 0;
int g_test_conntrack_get_full_key_hit = 0;
int g_test_conntrack_tcp_proxy_outbound_hit = 0;
int g_test_conntrack_tcp_proxy_return_hit = 0;
int g_test_conntrack_tcp_proxy_outbound_touch_count = 0;
int g_test_conntrack_tcp_proxy_return_touch_count = 0;
int g_test_conntrack_udp_proxy_outbound_hit = 0;
int g_test_conntrack_udp_proxy_return_hit = 0;
int g_test_conntrack_udp_proxy_outbound_touch_count = 0;
int g_test_conntrack_udp_proxy_return_touch_count = 0;
int g_test_dns_rewrite_request_hit = 0;
uint32_t g_test_dns_rewrite_request_ip = 0;
uint16_t g_test_dns_rewrite_request_port = 0;
int g_test_dns_rewrite_response_hit = 0;
uint32_t g_test_dns_rewrite_response_ip = 0;
uint16_t g_test_dns_rewrite_response_port = 0;
conntrack_entry_t g_test_conntrack_entry;
log_level_t g_test_log_enabled_level = LOG_INFO;
log_level_t g_test_log_last_level = LOG_LEVEL_COUNT;
char g_test_log_last_message[512];
int g_test_log_write_count = 0;
static conntrack_entry_t g_test_added_conntrack_entry;
static int g_test_added_conntrack_valid = 0;

int log_is_enabled(log_level_t level) {
    return level <= g_test_log_enabled_level;
}

void log_write(log_level_t level, const char *fmt, ...) {
    va_list args;

    g_test_log_last_level = level;
    va_start(args, fmt);
    vsnprintf(g_test_log_last_message, sizeof(g_test_log_last_message), fmt, args);
    va_end(args);
    g_test_log_write_count++;
}

int ndisapi_send_to_adapter(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf) {
    (void)engine;
    (void)buf;
    g_test_adapter_send_count++;
    return 1;
}

int ndisapi_send_to_mstcp(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf) {
    (void)engine;
    (void)buf;
    g_test_mstcp_send_count++;
    return 1;
}

void ndisapi_count_drop(ndisapi_engine_t *engine) {
    (void)engine;
    g_test_drop_count++;
}

void ndisapi_count_udp_forwarded(ndisapi_engine_t *engine) {
    (void)engine;
}

uint16_t ndisapi_next_tcp_relay_src_port(ndisapi_engine_t *engine) {
    (void)engine;
    return 40000;
}

uint32_t proc_lookup_tcp(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port,
                         char *name_out, int name_len) {
    (void)pl; (void)src_ip; (void)src_port;
    if (name_out && name_len > 0) name_out[0] = '\0';
    return 0;
}

uint32_t proc_lookup_udp(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port,
                         char *name_out, int name_len) {
    (void)pl; (void)src_ip; (void)src_port;
    if (name_out && name_len > 0) name_out[0] = '\0';
    return 0;
}

uint32_t proc_lookup_tcp_retry(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port,
                               char *name_out, int name_len) {
    (void)pl; (void)src_ip; (void)src_port;
    if (name_out && name_len > 0) name_out[0] = '\0';
    return 0;
}

uint32_t proc_lookup_udp_retry(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port,
                               char *name_out, int name_len) {
    (void)pl; (void)src_ip; (void)src_port;
    if (name_out && name_len > 0) name_out[0] = '\0';
    return 0;
}

int proc_is_self(proc_lookup_t *pl, uint32_t pid) {
    (void)pl; (void)pid;
    return 0;
}

int dns_hijack_is_dns_request(uint16_t dst_port) {
    return dst_port == 53 || dst_port == 5353;
}

int packet_dns_txid(packet_ctx_t *ctx, uint16_t *txid) {
    if (!ctx || !ctx->dns_txid_valid) return 0;
    if (txid) *txid = ctx->dns_txid;
    return 1;
}

int packet_dns_query_summary(packet_ctx_t *ctx, int tcp_framed,
                             packet_dns_query_summary_t *summary) {
    (void)tcp_framed;
    if (!summary) return 0;
    memset(summary, 0, sizeof(*summary));
    if (ctx && ctx->dns_txid_valid) {
        summary->txid = ctx->dns_txid;
        summary->txid_valid = 1;
    }
    return 0;
}

error_t conntrack_add_key_full(conntrack_t *ct, uint32_t key_src_ip, uint16_t key_src_port,
                               uint32_t key_dst_ip, uint16_t key_dst_port,
                               uint32_t client_ip, uint16_t client_port,
                               uint32_t orig_dst_ip, uint16_t orig_dst_port,
                               uint32_t connect_dst_ip, uint16_t connect_dst_port,
                               uint8_t protocol, uint32_t pid, const char *process_name,
                               uint32_t if_idx, uint32_t sub_if_idx,
                               uint16_t relay_src_port) {
    (void)ct;
    memset(&g_test_added_conntrack_entry, 0, sizeof(g_test_added_conntrack_entry));
    g_test_added_conntrack_entry.key_src_ip = key_src_ip;
    g_test_added_conntrack_entry.src_port = key_src_port;
    g_test_added_conntrack_entry.key_dst_ip = key_dst_ip;
    g_test_added_conntrack_entry.key_dst_port = key_dst_port;
    g_test_added_conntrack_entry.src_ip = client_ip;
    g_test_added_conntrack_entry.client_port = client_port;
    g_test_added_conntrack_entry.orig_dst_ip = orig_dst_ip;
    g_test_added_conntrack_entry.orig_dst_port = orig_dst_port;
    g_test_added_conntrack_entry.connect_dst_ip = connect_dst_ip;
    g_test_added_conntrack_entry.connect_dst_port = connect_dst_port;
    g_test_added_conntrack_entry.protocol = protocol;
    g_test_added_conntrack_entry.pid = pid;
    g_test_added_conntrack_entry.if_idx = if_idx;
    g_test_added_conntrack_entry.sub_if_idx = sub_if_idx;
    g_test_added_conntrack_entry.relay_src_port = relay_src_port;
    if (process_name) {
        strncpy(g_test_added_conntrack_entry.process_name, process_name,
                sizeof(g_test_added_conntrack_entry.process_name) - 1);
    }
    g_test_added_conntrack_valid = 1;
    return ERR_OK;
}

error_t conntrack_add(conntrack_t *ct, uint16_t src_port, uint32_t src_ip,
                      uint32_t orig_dst_ip, uint16_t orig_dst_port, uint8_t protocol,
                      uint32_t pid, const char *process_name,
                      uint32_t if_idx, uint32_t sub_if_idx) {
    (void)ct; (void)src_port; (void)src_ip; (void)orig_dst_ip;
    (void)orig_dst_port; (void)protocol; (void)pid; (void)process_name;
    (void)if_idx; (void)sub_if_idx;
    return ERR_OK;
}

error_t conntrack_add_key(conntrack_t *ct, uint32_t key_src_ip, uint16_t src_port,
                          uint32_t client_ip, uint32_t orig_dst_ip, uint16_t orig_dst_port,
                          uint8_t protocol, uint32_t pid, const char *process_name,
                          uint32_t if_idx, uint32_t sub_if_idx) {
    (void)ct; (void)key_src_ip; (void)src_port; (void)client_ip;
    (void)orig_dst_ip; (void)orig_dst_port; (void)protocol; (void)pid;
    (void)process_name; (void)if_idx; (void)sub_if_idx;
    return ERR_OK;
}

error_t conntrack_get_full_key(conntrack_t *ct, uint32_t src_ip, uint16_t src_port,
                               uint32_t dst_ip, uint16_t dst_port, uint8_t protocol,
                               conntrack_entry_t *out) {
    (void)ct; (void)src_ip; (void)src_port; (void)dst_ip; (void)dst_port; (void)protocol;
    if (g_test_added_conntrack_valid &&
        g_test_added_conntrack_entry.key_src_ip == src_ip &&
        g_test_added_conntrack_entry.src_port == src_port &&
        g_test_added_conntrack_entry.key_dst_ip == dst_ip &&
        g_test_added_conntrack_entry.key_dst_port == dst_port &&
        g_test_added_conntrack_entry.protocol == protocol) {
        if (out) *out = g_test_added_conntrack_entry;
        return ERR_OK;
    }
    if (!g_test_conntrack_get_full_key_hit) return ERR_NOT_FOUND;
    if (out) *out = g_test_conntrack_entry;
    return ERR_OK;
}

error_t conntrack_get_tcp_proxy_outbound(conntrack_t *ct, uint32_t client_ip,
                                         uint16_t client_port,
                                         uint32_t server_ip,
                                         uint16_t server_port,
                                         conntrack_entry_t *out) {
    (void)ct;
    if (g_test_added_conntrack_valid &&
        g_test_added_conntrack_entry.key_src_ip == client_ip &&
        g_test_added_conntrack_entry.src_port == client_port &&
        g_test_added_conntrack_entry.key_dst_ip == server_ip &&
        g_test_added_conntrack_entry.key_dst_port == server_port &&
        g_test_added_conntrack_entry.protocol == WTP_IPPROTO_TCP) {
        if (out) *out = g_test_added_conntrack_entry;
        return ERR_OK;
    }
    if (!g_test_conntrack_tcp_proxy_outbound_hit) return ERR_NOT_FOUND;
    if (out) *out = g_test_conntrack_entry;
    return ERR_OK;
}

error_t conntrack_get_tcp_proxy_return(conntrack_t *ct, uint32_t relay_src_ip,
                                       uint16_t relay_src_port,
                                       uint32_t relay_dst_ip,
                                       uint16_t relay_dst_port,
                                       conntrack_entry_t *out) {
    (void)ct;
    (void)relay_src_ip;
    (void)relay_src_port;
    (void)relay_dst_ip;
    (void)relay_dst_port;
    if (!g_test_conntrack_tcp_proxy_return_hit) return ERR_NOT_FOUND;
    if (out) *out = g_test_conntrack_entry;
    return ERR_OK;
}

error_t conntrack_get_udp_proxy_outbound(conntrack_t *ct, uint32_t client_ip,
                                         uint16_t client_port,
                                         conntrack_entry_t *out) {
    (void)ct;
    (void)client_ip;
    (void)client_port;
    if (!g_test_conntrack_udp_proxy_outbound_hit) return ERR_NOT_FOUND;
    if (out) *out = g_test_conntrack_entry;
    return ERR_OK;
}

error_t conntrack_get_udp_proxy_return(conntrack_t *ct, uint32_t server_ip,
                                       uint16_t client_port,
                                       conntrack_entry_t *out) {
    (void)ct;
    (void)server_ip;
    (void)client_port;
    if (!g_test_conntrack_udp_proxy_return_hit) return ERR_NOT_FOUND;
    if (out) *out = g_test_conntrack_entry;
    return ERR_OK;
}

error_t conntrack_get_full(conntrack_t *ct, uint32_t src_ip, uint16_t src_port,
                           uint8_t protocol, conntrack_entry_t *out) {
    return conntrack_get_full_key(ct, src_ip, src_port, 0, 0, protocol, out);
}

error_t conntrack_get(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol,
                      uint32_t *orig_dst_ip, uint16_t *orig_dst_port) {
    conntrack_entry_t entry;
    error_t err = conntrack_get_full(ct, src_ip, src_port, protocol, &entry);
    if (err != ERR_OK) return err;
    if (orig_dst_ip) *orig_dst_ip = entry.orig_dst_ip;
    if (orig_dst_port) *orig_dst_port = entry.orig_dst_port;
    return ERR_OK;
}

void conntrack_remove_key(conntrack_t *ct, uint32_t src_ip, uint16_t src_port,
                          uint32_t dst_ip, uint16_t dst_port, uint8_t protocol) {
    (void)ct; (void)src_ip; (void)src_port; (void)dst_ip; (void)dst_port; (void)protocol;
}

void conntrack_remove(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol) {
    (void)ct; (void)src_ip; (void)src_port; (void)protocol;
}

void conntrack_touch_key(conntrack_t *ct, uint32_t src_ip, uint16_t src_port,
                         uint32_t dst_ip, uint16_t dst_port, uint8_t protocol) {
    (void)ct; (void)src_ip; (void)src_port; (void)dst_ip; (void)dst_port; (void)protocol;
}

void conntrack_touch_tcp_proxy_outbound(conntrack_t *ct,
                                        const conntrack_entry_t *entry) {
    (void)ct;
    (void)entry;
    g_test_conntrack_tcp_proxy_outbound_touch_count++;
}

void conntrack_touch_tcp_proxy_return(conntrack_t *ct,
                                      const conntrack_entry_t *entry) {
    (void)ct;
    (void)entry;
    g_test_conntrack_tcp_proxy_return_touch_count++;
}

void conntrack_touch_udp_proxy_outbound(conntrack_t *ct,
                                        const conntrack_entry_t *entry) {
    (void)ct;
    (void)entry;
    g_test_conntrack_udp_proxy_outbound_touch_count++;
}

void conntrack_touch_udp_proxy_return(conntrack_t *ct,
                                      const conntrack_entry_t *entry) {
    (void)ct;
    (void)entry;
    g_test_conntrack_udp_proxy_return_touch_count++;
}

void conntrack_touch(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol) {
    (void)ct; (void)src_ip; (void)src_port; (void)protocol;
}

error_t dns_hijack_forward_query(dns_hijack_t *dh, const uint8_t *dns_payload, int dns_len,
                                 uint16_t src_port, uint32_t original_dns_ip, uint16_t original_dns_port,
                                 uint32_t client_ip, HANDLE adapter_handle) {
    (void)dh;
    (void)dns_payload;
    (void)dns_len;
    (void)src_port;
    (void)original_dns_ip;
    (void)original_dns_port;
    (void)client_ip;
    (void)adapter_handle;
    return ERR_OK;
}

int dns_hijack_rewrite_request(dns_hijack_t *dh, uint32_t *dst_ip, uint16_t *dst_port,
                               uint16_t src_port, uint16_t dns_txid,
                               uint32_t original_dns_ip, uint16_t original_dns_port,
                               uint32_t client_ip, HANDLE adapter_handle) {
    (void)dh;
    (void)src_port;
    (void)dns_txid;
    (void)original_dns_ip;
    (void)original_dns_port;
    (void)client_ip;
    (void)adapter_handle;
    if (!g_test_dns_rewrite_request_hit) return 0;
    if (dst_ip) *dst_ip = g_test_dns_rewrite_request_ip;
    if (dst_port) *dst_port = g_test_dns_rewrite_request_port;
    return 1;
}

int dns_hijack_rewrite_response(dns_hijack_t *dh, uint32_t *src_ip, uint16_t *src_port,
                                uint16_t dst_port, uint16_t dns_txid) {
    (void)dh;
    (void)dst_port;
    (void)dns_txid;
    if (!g_test_dns_rewrite_response_hit) return 0;
    if (src_ip) *src_ip = g_test_dns_rewrite_response_ip;
    if (src_port) *src_port = g_test_dns_rewrite_response_port;
    return 1;
}

int packet_payload(packet_ctx_t *ctx, const uint8_t **payload, UINT *payload_len) {
    if (ctx && ctx->payload_valid) {
        if (payload) *payload = ctx->payload_data;
        if (payload_len) *payload_len = ctx->payload_len;
        return 1;
    }
    if (payload) *payload = NULL;
    if (payload_len) *payload_len = 0;
    return 0;
}

void packet_recalculate_checksums(packet_ctx_t *ctx) {
    (void)ctx;
}

int packet_clamp_tcp_mss(packet_ctx_t *ctx, uint16_t max_mss) {
    (void)ctx;
    (void)max_mss;
    return 0;
}

void test_reset_conntrack_stub_state(void) {
    memset(&g_test_added_conntrack_entry, 0, sizeof(g_test_added_conntrack_entry));
    g_test_added_conntrack_valid = 0;
}
