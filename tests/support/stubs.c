#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "app/log.h"
#include "conntrack/conntrack.h"
#include "core/common.h"
#include "flow/action.h"
#include "ndisapi/adapter.h"
#include "process/lookup.h"

int g_test_adapter_send_count = 0;
int g_test_mstcp_send_count = 0;
int g_test_adapter_send_call_count = 0;
int g_test_mstcp_send_call_count = 0;
INTERMEDIATE_BUFFER g_test_last_mstcp_packet;
int g_test_last_mstcp_packet_valid = 0;
int g_test_mstcp_send_error = 0;
int g_test_send_failure_count = 0;
int g_test_drop_count = 0;
int g_test_udp_forwarded_count = 0;
int g_test_dns_forwarded_count = 0;
int g_test_dns_forward_error = 0;
int g_test_conntrack_get_full_key_hit = 0;
int g_test_conntrack_tcp_proxy_outbound_hit = 0;
int g_test_conntrack_tcp_proxy_return_hit = 0;
int g_test_conntrack_tcp_proxy_outbound_touch_count = 0;
int g_test_conntrack_tcp_proxy_return_touch_count = 0;
int g_test_conntrack_udp_proxy_outbound_hit = 0;
int g_test_conntrack_udp_proxy_return_hit = 0;
int g_test_conntrack_udp_proxy_outbound_touch_count = 0;
int g_test_conntrack_udp_proxy_return_touch_count = 0;
int g_test_conntrack_raw_full_key_add_count = 0;
int g_test_conntrack_direct_tcp_track_count = 0;
int g_test_conntrack_tcp_proxy_track_count = 0;
int g_test_conntrack_udp_proxy_track_count = 0;
int g_test_conntrack_tcp_dns_track_count = 0;
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

static void test_store_conntrack_entry(uint32_t key_src_ip, uint16_t key_src_port,
                                       uint32_t key_dst_ip, uint16_t key_dst_port,
                                       uint32_t client_ip, uint16_t client_port,
                                       uint32_t orig_dst_ip, uint16_t orig_dst_port,
                                       uint32_t connect_dst_ip, uint16_t connect_dst_port,
                                       uint8_t protocol, uint32_t pid,
                                       const char *process_name,
                                       uint32_t if_idx, uint32_t sub_if_idx,
                                       uint16_t relay_src_port) {
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
}

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

int ndisapi_send_batch_to_adapter(ndisapi_engine_t *engine,
                                  PINTERMEDIATE_BUFFER *bufs,
                                  DWORD count) {
    (void)engine;
    (void)bufs;
    if (count > 0) {
        g_test_adapter_send_call_count++;
        g_test_adapter_send_count += (int)count;
    }
    return 1;
}

int ndisapi_send_batch_to_mstcp(ndisapi_engine_t *engine,
                                PINTERMEDIATE_BUFFER *bufs,
                                DWORD count) {
    (void)engine;
    (void)bufs;
    if (count > 0) {
        g_test_mstcp_send_call_count++;
        if (g_test_mstcp_send_error) {
            g_test_send_failure_count += (int)count;
            return 0;
        }
        g_test_mstcp_send_count += (int)count;
        if (bufs && bufs[count - 1]) {
            g_test_last_mstcp_packet = *bufs[count - 1];
            g_test_last_mstcp_packet_valid = 1;
        }
    }
    return 1;
}

int ndisapi_enqueue_send_batch_to_adapter(ndisapi_engine_t *engine,
                                          ndisapi_send_item_t *items,
                                          DWORD count) {
    (void)engine;
    if (count > 0) {
        g_test_adapter_send_call_count++;
        g_test_adapter_send_count += (int)count;
        for (DWORD i = 0; i < count; i++) {
            if (items && items[i].free_after_send && items[i].buf) {
                free(items[i].buf);
            }
        }
    }
    return 1;
}

int ndisapi_enqueue_send_batch_to_mstcp(ndisapi_engine_t *engine,
                                        ndisapi_send_item_t *items,
                                        DWORD count) {
    (void)engine;
    if (count > 0) {
        g_test_mstcp_send_call_count++;
        if (g_test_mstcp_send_error) {
            g_test_send_failure_count += (int)count;
            for (DWORD i = 0; i < count; i++) {
                if (items && items[i].free_after_send && items[i].buf) {
                    free(items[i].buf);
                }
            }
            return 0;
        }
        g_test_mstcp_send_count += (int)count;
        if (items && items[count - 1].buf) {
            g_test_last_mstcp_packet = *items[count - 1].buf;
            g_test_last_mstcp_packet_valid = 1;
        }
        for (DWORD i = 0; i < count; i++) {
            if (items && items[i].free_after_send && items[i].buf) {
                free(items[i].buf);
            }
        }
    }
    return 1;
}

int ndisapi_send_to_adapter(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf) {
    return ndisapi_send_batch_to_adapter(engine, &buf, 1);
}

int ndisapi_send_to_mstcp(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf) {
    return ndisapi_send_batch_to_mstcp(engine, &buf, 1);
}

void ndisapi_count_drop(ndisapi_engine_t *engine) {
    (void)engine;
    g_test_drop_count++;
}

void ndisapi_count_udp_forwarded(ndisapi_engine_t *engine) {
    (void)engine;
    g_test_udp_forwarded_count++;
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

void packet_refresh_observation(packet_ctx_t *ctx) {
    packet_observation_t *obs;

    if (!ctx) return;

    obs = &ctx->observation;
    memset(obs, 0, sizeof(*obs));
    obs->ctx = ctx;
    obs->ndis_buf = ctx->ndis_buf;
    obs->adapter_handle = ctx->adapter_handle;
    if (!obs->adapter_handle && ctx->ndis_buf) {
        obs->adapter_handle = ctx->ndis_buf->m_hAdapter;
    }
    obs->src_ip = ctx->src_ip;
    obs->dst_ip = ctx->dst_ip;
    obs->src_port = ctx->src_port;
    obs->dst_port = ctx->dst_port;
    obs->protocol = ctx->protocol;
    obs->has_tcp = ctx->tcp_hdr != NULL;
    obs->has_udp = ctx->udp_hdr != NULL;
    obs->tcp_flags = ctx->tcp_hdr ? ctx->tcp_hdr->th_flags : 0;
    obs->outbound = ctx->ndis_buf &&
        ((ctx->ndis_buf->m_dwDeviceFlags & PACKET_FLAG_ON_SEND) != 0);
    obs->inbound = ctx->ndis_buf &&
        ((ctx->ndis_buf->m_dwDeviceFlags & PACKET_FLAG_ON_RECEIVE) != 0);
    obs->payload_data = ctx->payload_data;
    obs->payload_len = ctx->payload_len;
    obs->payload_valid = ctx->payload_valid;
    obs->dns_txid = ctx->dns_txid;
    obs->dns_txid_valid = ctx->dns_txid_valid;
}

const packet_observation_t *packet_observe(packet_ctx_t *ctx) {
    if (!ctx) return NULL;
    packet_refresh_observation(ctx);
    return &ctx->observation;
}

packet_ctx_t *packet_observation_context(const packet_observation_t *obs) {
    return obs ? obs->ctx : NULL;
}

int packet_payload_observed(const packet_observation_t *obs,
                            const uint8_t **payload, UINT *payload_len) {
    if (obs && obs->payload_valid) {
        if (payload) *payload = obs->payload_data;
        if (payload_len) *payload_len = obs->payload_len;
        return 1;
    }
    if (payload) *payload = NULL;
    if (payload_len) *payload_len = 0;
    return 0;
}

int packet_dns_txid(packet_ctx_t *ctx, uint16_t *txid) {
    if (!ctx || !ctx->dns_txid_valid) return 0;
    if (txid) *txid = ctx->dns_txid;
    return 1;
}

int packet_dns_txid_observed(const packet_observation_t *obs, uint16_t *txid) {
    if (!obs || !obs->dns_txid_valid) return 0;
    if (txid) *txid = obs->dns_txid;
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

int packet_dns_query_summary_observed(const packet_observation_t *obs,
                                      int tcp_framed,
                                      packet_dns_query_summary_t *summary) {
    (void)tcp_framed;
    if (!summary) return 0;
    memset(summary, 0, sizeof(*summary));
    if (obs && obs->dns_txid_valid) {
        summary->txid = obs->dns_txid;
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
    g_test_conntrack_raw_full_key_add_count++;
    test_store_conntrack_entry(key_src_ip, key_src_port,
                               key_dst_ip, key_dst_port,
                               client_ip, client_port,
                               orig_dst_ip, orig_dst_port,
                               connect_dst_ip, connect_dst_port,
                               protocol, pid, process_name,
                               if_idx, sub_if_idx, relay_src_port);
    return ERR_OK;
}

error_t conntrack_track_direct_tcp(conntrack_t *ct,
                                   const conntrack_direct_tcp_flow_t *flow) {
    (void)ct;
    if (!flow) return ERR_PARAM;
    g_test_conntrack_direct_tcp_track_count++;
    test_store_conntrack_entry(flow->client_ip, flow->client_port,
                               flow->server_ip, flow->server_port,
                               flow->client_ip, flow->client_port,
                               flow->server_ip, flow->server_port,
                               flow->server_ip, flow->server_port,
                               WTP_IPPROTO_TCP, flow->pid,
                               flow->process_name,
                               flow->if_idx, flow->sub_if_idx, 0);
    return ERR_OK;
}

error_t conntrack_track_tcp_proxy(conntrack_t *ct,
                                  const conntrack_tcp_proxy_flow_t *flow,
                                  uint16_t *relay_src_port_out) {
    uint16_t relay_src_port;

    (void)ct;
    if (!flow) return ERR_PARAM;
    g_test_conntrack_tcp_proxy_track_count++;
    relay_src_port = flow->proposed_relay_src_port ?
        flow->proposed_relay_src_port : flow->client_port;
    if (relay_src_port_out) *relay_src_port_out = relay_src_port;
    test_store_conntrack_entry(flow->client_ip, flow->client_port,
                               flow->server_ip, flow->server_port,
                               flow->client_ip, flow->client_port,
                               flow->server_ip, flow->server_port,
                               flow->server_ip, flow->server_port,
                               WTP_IPPROTO_TCP, flow->pid,
                               flow->process_name,
                               flow->if_idx, flow->sub_if_idx,
                               relay_src_port);
    return ERR_OK;
}

error_t conntrack_track_udp_proxy(conntrack_t *ct,
                                  const conntrack_udp_proxy_flow_t *flow) {
    (void)ct;
    if (!flow) return ERR_PARAM;
    g_test_conntrack_udp_proxy_track_count++;
    test_store_conntrack_entry(flow->client_ip, flow->client_port,
                               0, 0,
                               flow->client_ip, flow->client_port,
                               flow->server_ip, flow->server_port,
                               flow->server_ip, flow->server_port,
                               WTP_IPPROTO_UDP, flow->pid,
                               flow->process_name,
                               flow->if_idx, flow->sub_if_idx,
                               flow->client_port);
    return ERR_OK;
}

error_t conntrack_track_tcp_dns(conntrack_t *ct,
                                const conntrack_tcp_dns_flow_t *flow) {
    uint32_t key_src_ip;

    (void)ct;
    if (!flow) return ERR_PARAM;
    g_test_conntrack_tcp_dns_track_count++;
    key_src_ip = flow->loopback_redirect ?
        flow->original_dns_ip : flow->client_ip;
    test_store_conntrack_entry(key_src_ip, flow->client_port,
                               flow->redirect_ip, flow->redirect_port,
                               flow->client_ip, flow->client_port,
                               flow->original_dns_ip,
                               flow->original_dns_port,
                               flow->redirect_ip, flow->redirect_port,
                               WTP_IPPROTO_TCP, 0, "",
                               flow->if_idx, flow->sub_if_idx,
                               flow->client_port);
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

error_t conntrack_get_tcp_dns_return(conntrack_t *ct, uint32_t response_src_ip,
                                     uint16_t response_src_port,
                                     uint32_t response_dst_ip,
                                     uint16_t response_dst_port,
                                     conntrack_entry_t *out) {
    return conntrack_get_full_key(ct, response_dst_ip, response_dst_port,
                                  response_src_ip, response_src_port,
                                  WTP_IPPROTO_TCP, out);
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

void conntrack_touch_direct_tcp(conntrack_t *ct,
                                const conntrack_entry_t *entry) {
    (void)ct;
    (void)entry;
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
    if (g_test_dns_forward_error != 0) {
        return (error_t)g_test_dns_forward_error;
    }
    g_test_dns_forwarded_count++;
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

void RecalculateIPChecksum(PINTERMEDIATE_BUFFER pPacket) {
    (void)pPacket;
}

void RecalculateTCPChecksum(PINTERMEDIATE_BUFFER pPacket) {
    (void)pPacket;
}

void RecalculateUDPChecksum(PINTERMEDIATE_BUFFER pPacket) {
    (void)pPacket;
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
