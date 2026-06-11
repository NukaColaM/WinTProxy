#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "app/config.h"
#include "app/log.h"
#include "conntrack/conntrack.h"
#include "dns/hijack.h"
#include "flow/action.h"
#include "flow/executor.h"
#include "net/headers.h"
#include "ndisapi/adapter.h"
#include "process/lookup.h"

int g_test_windows_create_thread_count = 0;
LPTHREAD_START_ROUTINE g_test_windows_thread_procs[64];
LPVOID g_test_windows_thread_params[64];
int g_test_windows_set_event_count = 0;
HANDLE g_test_windows_set_event_handles[128];

static int failures = 0;
static HANDLE adapter_a = (HANDLE)0xA001;
static HANDLE adapter_b = (HANDLE)0xB002;
static HANDLE packet_events[NDISAPI_MAX_ADAPTERS];
static HANDLE packet_event_adapters[NDISAPI_MAX_ADAPTERS];
static int packet_event_count = 0;
static int adapter_mode_count = 0;
static int adapter_mode_reset_count = 0;
static int packet_event_release_count = 0;
static int adapter_change_event_count = 0;
static HANDLE adapter_change_event = NULL;
static int flush_adapter_queue_count = 0;
static HANDLE flush_adapter_queue_adapters[16];
static int read_packets_count = 0;
static int read_packets_unsorted_count = 0;
static HANDLE read_packets_adapters[16];
static unsigned read_packets_numbers[16];
static int mstcp_unsorted_send_count = 0;
static int adapter_unsorted_send_count = 0;
static int mstcp_send_call_count = 0;
static int adapter_send_call_count = 0;
static HANDLE mstcp_send_adapters[16];
static HANDLE adapter_send_adapters[16];
static unsigned mstcp_send_numbers[16];
static unsigned adapter_send_numbers[16];
static int mstcp_partial_next = 0;
static int adapter_fail_next = 0;
static int log_capture_enabled = 0;
static int log_write_count = 0;
static char log_last_message[512];
static ndisapi_engine_t *engine_to_stop_after_read = NULL;

static void check_int(const char *name, int actual, int expected) {
    if (actual != expected) {
        fprintf(stderr, "FAIL %s: got %d expected %d\n", name, actual, expected);
        failures++;
    }
}

static void check_handle_not_equal(const char *name, HANDLE a, HANDLE b) {
    if (a == b) {
        fprintf(stderr, "FAIL %s: handles should differ\n", name);
        failures++;
    }
}

static void check_handle(const char *name, HANDLE actual, HANDLE expected) {
    if (actual != expected) {
        fprintf(stderr, "FAIL %s: got %p expected %p\n", name, actual, expected);
        failures++;
    }
}

static void check_contains(const char *name, const char *actual,
                           const char *needle) {
    if (!actual || !strstr(actual, needle)) {
        fprintf(stderr, "FAIL %s: '%s' should contain '%s'\n", name,
                actual ? actual : "", needle);
        failures++;
    }
}

static void fill_inbound_ipv4_udp(PINTERMEDIATE_BUFFER buf, HANDLE adapter) {
    uint8_t *p;

    memset(buf, 0, sizeof(*buf));
    buf->m_hAdapter = adapter;
    buf->m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    buf->m_Length = ETHER_HDR_LEN + 20 + 8;

    p = buf->m_IBuffer;
    memset(p, 0, buf->m_Length);
    p[12] = 0x08;
    p[13] = 0x00;

    p += ETHER_HDR_LEN;
    p[0] = 0x45;
    p[2] = 0x00;
    p[3] = 28;
    p[8] = 64;
    p[9] = WTP_IPPROTO_UDP;
    p[12] = 198;
    p[13] = 51;
    p[14] = 100;
    p[15] = 10;
    p[16] = 10;
    p[17] = 0;
    p[18] = 0;
    p[19] = 5;

    p += 20;
    p[0] = 0x30;
    p[1] = 0x39;
    p[2] = 0x01;
    p[3] = 0xbb;
    p[4] = 0x00;
    p[5] = 0x08;
}

static void fill_ipv4_udp_packet(PINTERMEDIATE_BUFFER buf, HANDLE adapter,
                                 DWORD flags,
                                 uint32_t src_ip, uint16_t src_port,
                                 uint32_t dst_ip, uint16_t dst_port) {
    uint8_t *p;

    memset(buf, 0, sizeof(*buf));
    buf->m_hAdapter = adapter;
    buf->m_dwDeviceFlags = flags;
    buf->m_Length = ETHER_HDR_LEN + 20 + 8;

    p = buf->m_IBuffer;
    memset(p, 0, buf->m_Length);
    p[12] = 0x08;
    p[13] = 0x00;

    p += ETHER_HDR_LEN;
    p[0] = 0x45;
    p[2] = 0x00;
    p[3] = 28;
    p[8] = 64;
    p[9] = WTP_IPPROTO_UDP;
    p[12] = (uint8_t)(src_ip >> 24);
    p[13] = (uint8_t)(src_ip >> 16);
    p[14] = (uint8_t)(src_ip >> 8);
    p[15] = (uint8_t)src_ip;
    p[16] = (uint8_t)(dst_ip >> 24);
    p[17] = (uint8_t)(dst_ip >> 16);
    p[18] = (uint8_t)(dst_ip >> 8);
    p[19] = (uint8_t)dst_ip;

    p += 20;
    p[0] = (uint8_t)(src_port >> 8);
    p[1] = (uint8_t)src_port;
    p[2] = (uint8_t)(dst_port >> 8);
    p[3] = (uint8_t)dst_port;
    p[4] = 0x00;
    p[5] = 0x08;
}

static int run_captured_thread(LPVOID param) {
    int i;

    for (i = 0; i < g_test_windows_create_thread_count && i < 64; i++) {
        if (g_test_windows_thread_params[i] == param &&
            g_test_windows_thread_procs[i]) {
            g_test_windows_thread_procs[i](param);
            return 1;
        }
    }
    return 0;
}

static void reset_test_state(void) {
    memset(packet_events, 0, sizeof(packet_events));
    memset(packet_event_adapters, 0, sizeof(packet_event_adapters));
    memset(g_test_windows_set_event_handles, 0,
           sizeof(g_test_windows_set_event_handles));
    memset(flush_adapter_queue_adapters, 0, sizeof(flush_adapter_queue_adapters));
    memset(read_packets_adapters, 0, sizeof(read_packets_adapters));
    memset(read_packets_numbers, 0, sizeof(read_packets_numbers));
    memset(mstcp_send_adapters, 0, sizeof(mstcp_send_adapters));
    memset(adapter_send_adapters, 0, sizeof(adapter_send_adapters));
    memset(mstcp_send_numbers, 0, sizeof(mstcp_send_numbers));
    memset(adapter_send_numbers, 0, sizeof(adapter_send_numbers));
    memset(g_test_windows_thread_procs, 0, sizeof(g_test_windows_thread_procs));
    memset(g_test_windows_thread_params, 0, sizeof(g_test_windows_thread_params));
    memset(log_last_message, 0, sizeof(log_last_message));
    g_test_windows_create_thread_count = 0;
    g_test_windows_set_event_count = 0;
    packet_event_count = 0;
    adapter_mode_count = 0;
    adapter_mode_reset_count = 0;
    packet_event_release_count = 0;
    adapter_change_event_count = 0;
    adapter_change_event = NULL;
    flush_adapter_queue_count = 0;
    read_packets_count = 0;
    read_packets_unsorted_count = 0;
    mstcp_unsorted_send_count = 0;
    adapter_unsorted_send_count = 0;
    mstcp_send_call_count = 0;
    adapter_send_call_count = 0;
    mstcp_partial_next = 0;
    adapter_fail_next = 0;
    log_capture_enabled = 0;
    log_write_count = 0;
    engine_to_stop_after_read = NULL;
}

static void clear_send_capture(void) {
    memset(mstcp_send_adapters, 0, sizeof(mstcp_send_adapters));
    memset(adapter_send_adapters, 0, sizeof(adapter_send_adapters));
    memset(mstcp_send_numbers, 0, sizeof(mstcp_send_numbers));
    memset(adapter_send_numbers, 0, sizeof(adapter_send_numbers));
    mstcp_send_call_count = 0;
    adapter_send_call_count = 0;
    mstcp_unsorted_send_count = 0;
    adapter_unsorted_send_count = 0;
}

int log_is_enabled(log_level_t level) {
    (void)level;
    return log_capture_enabled;
}

void log_write(log_level_t level, const char *fmt, ...) {
    va_list args;

    (void)level;
    va_start(args, fmt);
    vsnprintf(log_last_message, sizeof(log_last_message), fmt, args);
    va_end(args);
    log_write_count++;
}

HANDLE __stdcall OpenFilterDriver(const wchar_t *pszFileName) {
    (void)pszFileName;
    return (HANDLE)0xD001;
}

VOID __stdcall CloseFilterDriver(HANDLE hOpen) {
    (void)hOpen;
}

DWORD __stdcall GetDriverVersion(HANDLE hOpen) {
    (void)hOpen;
    return 0x03062000;
}

BOOL __stdcall IsDriverLoaded(HANDLE hOpen) {
    (void)hOpen;
    return TRUE;
}

BOOL __stdcall GetTcpipBoundAdaptersInfo(HANDLE hOpen, PTCP_AdapterList pAdapters) {
    (void)hOpen;
    memset(pAdapters, 0, sizeof(*pAdapters));
    pAdapters->m_nAdapterCount = 2;
    pAdapters->m_nAdapterHandle[0] = adapter_a;
    pAdapters->m_nAdapterHandle[1] = adapter_b;
    memcpy(pAdapters->m_szAdapterNameList[0], "adapter-a", 9);
    memcpy(pAdapters->m_szAdapterNameList[1], "adapter-b", 9);
    pAdapters->m_czCurrentAddress[0][0] = 0x0a;
    pAdapters->m_czCurrentAddress[1][0] = 0x0b;
    pAdapters->m_usMTU[0] = 1500;
    pAdapters->m_usMTU[1] = 1500;
    return TRUE;
}

BOOL __stdcall ConvertWindows2000AdapterName(LPCSTR szAdapterName,
                                             LPSTR szUserFriendlyName,
                                             DWORD len) {
    snprintf(szUserFriendlyName, len, "%s-friendly", szAdapterName);
    return TRUE;
}

BOOL __stdcall SetPacketEvent(HANDLE hOpen, HANDLE hAdapter, HANDLE hWin32Event) {
    (void)hOpen;
    if (hWin32Event && packet_event_count < NDISAPI_MAX_ADAPTERS) {
        packet_event_adapters[packet_event_count] = hAdapter;
        packet_events[packet_event_count] = hWin32Event;
        packet_event_count++;
    } else if (!hWin32Event) {
        (void)hAdapter;
        packet_event_release_count++;
    }
    return TRUE;
}

BOOL __stdcall SetAdapterMode(HANDLE hOpen, PADAPTER_MODE pMode) {
    (void)hOpen;
    if (pMode && pMode->dwFlags != 0) {
        adapter_mode_count++;
    } else if (pMode) {
        adapter_mode_reset_count++;
    }
    return TRUE;
}

BOOL __stdcall SetAdapterListChangeEvent(HANDLE hOpen, HANDLE hWin32Event) {
    (void)hOpen;
    adapter_change_event = hWin32Event;
    if (hWin32Event) adapter_change_event_count++;
    return TRUE;
}

BOOL __stdcall SetPoolSize(DWORD dwPoolSize) {
    (void)dwPoolSize;
    return TRUE;
}

BOOL __stdcall FlushAdapterPacketQueue(HANDLE hOpen, HANDLE hAdapter) {
    (void)hOpen;
    if (flush_adapter_queue_count < 16) {
        flush_adapter_queue_adapters[flush_adapter_queue_count] = hAdapter;
    }
    flush_adapter_queue_count++;
    return TRUE;
}

BOOL __stdcall ReadPackets(HANDLE hOpen, PETH_M_REQUEST pPackets) {
    (void)hOpen;
    if (read_packets_count < 16) {
        read_packets_adapters[read_packets_count] = pPackets->hAdapterHandle;
        read_packets_numbers[read_packets_count] = pPackets->dwPacketsNumber;
    }
    read_packets_count++;

    if (!pPackets || pPackets->hAdapterHandle != adapter_a) {
        pPackets->dwPacketsSuccess = 0;
        if (engine_to_stop_after_read) engine_to_stop_after_read->running = 0;
        return TRUE;
    }

    if (pPackets->dwPacketsNumber == 0 || !pPackets->EthPacket[0].Buffer) {
        if (engine_to_stop_after_read) engine_to_stop_after_read->running = 0;
        return FALSE;
    }

    fill_inbound_ipv4_udp(pPackets->EthPacket[0].Buffer, pPackets->hAdapterHandle);
    pPackets->dwPacketsSuccess = 1;
    if (engine_to_stop_after_read) engine_to_stop_after_read->running = 0;
    return TRUE;
}

BOOL __stdcall ReadPacketsUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER *Packets,
                                   DWORD dwPacketsNum, PDWORD pdwPacketsSuccess) {
    (void)hOpen;
    (void)Packets;
    (void)dwPacketsNum;
    read_packets_unsorted_count++;
    if (pdwPacketsSuccess) *pdwPacketsSuccess = 0;
    if (engine_to_stop_after_read) engine_to_stop_after_read->running = 0;
    return FALSE;
}

BOOL __stdcall SendPacketsToMstcpUnsorted(HANDLE hOpen,
                                          PINTERMEDIATE_BUFFER *Packets,
                                          DWORD dwPacketsNum,
                                          PDWORD pdwPacketSuccess) {
    (void)hOpen;
    (void)Packets;
    mstcp_unsorted_send_count += (int)dwPacketsNum;
    if (pdwPacketSuccess) *pdwPacketSuccess = dwPacketsNum;
    return TRUE;
}

BOOL __stdcall SendPacketsToAdaptersUnsorted(HANDLE hOpen,
                                             PINTERMEDIATE_BUFFER *Packets,
                                             DWORD dwPacketsNum,
                                             PDWORD pdwPacketSuccess) {
    (void)hOpen;
    (void)Packets;
    adapter_unsorted_send_count += (int)dwPacketsNum;
    if (pdwPacketSuccess) *pdwPacketSuccess = dwPacketsNum;
    return TRUE;
}

BOOL __stdcall SendPacketsToMstcp(HANDLE hOpen, PETH_M_REQUEST pPackets) {
    (void)hOpen;
    if (pPackets && mstcp_send_call_count < 16) {
        mstcp_send_adapters[mstcp_send_call_count] = pPackets->hAdapterHandle;
        mstcp_send_numbers[mstcp_send_call_count] = pPackets->dwPacketsNumber;
    }
    mstcp_send_call_count++;
    if (pPackets) {
        if (mstcp_partial_next && pPackets->dwPacketsNumber > 0) {
            mstcp_partial_next = 0;
            pPackets->dwPacketsSuccess = pPackets->dwPacketsNumber - 1U;
        } else {
            pPackets->dwPacketsSuccess = pPackets->dwPacketsNumber;
        }
    }
    return TRUE;
}

BOOL __stdcall SendPacketsToAdapter(HANDLE hOpen, PETH_M_REQUEST pPackets) {
    (void)hOpen;
    if (pPackets && adapter_send_call_count < 16) {
        adapter_send_adapters[adapter_send_call_count] = pPackets->hAdapterHandle;
        adapter_send_numbers[adapter_send_call_count] = pPackets->dwPacketsNumber;
    }
    adapter_send_call_count++;
    if (adapter_fail_next) {
        adapter_fail_next = 0;
        if (pPackets) pPackets->dwPacketsSuccess = 0;
        return FALSE;
    }
    if (pPackets) pPackets->dwPacketsSuccess = pPackets->dwPacketsNumber;
    return TRUE;
}

void __stdcall RecalculateIPChecksum(PINTERMEDIATE_BUFFER pPacket) {
    (void)pPacket;
}

void __stdcall RecalculateTCPChecksum(PINTERMEDIATE_BUFFER pPacket) {
    (void)pPacket;
}

void __stdcall RecalculateUDPChecksum(PINTERMEDIATE_BUFFER pPacket) {
    (void)pPacket;
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
    return proc_lookup_tcp(pl, src_ip, src_port, name_out, name_len);
}

uint32_t proc_lookup_udp_retry(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port,
                               char *name_out, int name_len) {
    return proc_lookup_udp(pl, src_ip, src_port, name_out, name_len);
}

int proc_is_self(proc_lookup_t *pl, uint32_t pid) {
    (void)pl; (void)pid;
    return 0;
}

int dns_hijack_is_dns_request(uint16_t dst_port) {
    return dst_port == 53;
}

error_t dns_hijack_forward_query(dns_hijack_t *dh, const uint8_t *dns_payload,
                                 int dns_len, uint16_t src_port,
                                 uint32_t original_dns_ip,
                                 uint16_t original_dns_port,
                                 uint32_t client_ip,
                                 HANDLE adapter_handle) {
    (void)dh; (void)dns_payload; (void)dns_len; (void)src_port;
    (void)original_dns_ip; (void)original_dns_port; (void)client_ip;
    (void)adapter_handle;
    return ERR_OK;
}

error_t dns_hijack_start_forwarder(dns_hijack_t *dh, void *engine_ctx) {
    (void)dh;
    (void)engine_ctx;
    return ERR_OK;
}

void dns_hijack_shutdown(dns_hijack_t *dh) {
    (void)dh;
}

int dns_hijack_rewrite_request(dns_hijack_t *dh, uint32_t *dst_ip,
                               uint16_t *dst_port, uint16_t src_port,
                               uint16_t dns_txid, uint32_t original_dns_ip,
                               uint16_t original_dns_port, uint32_t client_ip,
                               HANDLE adapter_handle) {
    (void)dh; (void)dst_ip; (void)dst_port; (void)src_port; (void)dns_txid;
    (void)original_dns_ip; (void)original_dns_port; (void)client_ip;
    (void)adapter_handle;
    return 0;
}

int dns_hijack_rewrite_response(dns_hijack_t *dh, uint32_t *src_ip,
                                uint16_t *src_port, uint16_t dst_port,
                                uint16_t dns_txid) {
    (void)dh; (void)src_ip; (void)src_port; (void)dst_port; (void)dns_txid;
    return 0;
}

error_t conntrack_get_tcp_dns_return(conntrack_t *ct, uint32_t response_src_ip,
                                     uint16_t response_src_port,
                                     uint32_t response_dst_ip,
                                     uint16_t response_dst_port,
                                     conntrack_entry_t *out) {
    (void)ct; (void)response_src_ip; (void)response_src_port;
    (void)response_dst_ip; (void)response_dst_port; (void)out;
    return ERR_NOT_FOUND;
}

error_t conntrack_get_tcp_proxy_return(conntrack_t *ct, uint32_t relay_src_ip,
                                       uint16_t relay_src_port,
                                       uint32_t relay_dst_ip,
                                       uint16_t relay_dst_port,
                                       conntrack_entry_t *out) {
    (void)ct; (void)relay_src_ip; (void)relay_src_port;
    (void)relay_dst_ip; (void)relay_dst_port; (void)out;
    return ERR_NOT_FOUND;
}

error_t conntrack_get_udp_proxy_return(conntrack_t *ct, uint32_t server_ip,
                                       uint16_t client_port,
                                       conntrack_entry_t *out) {
    (void)ct; (void)server_ip; (void)client_port; (void)out;
    return ERR_NOT_FOUND;
}

error_t conntrack_get_tcp_proxy_outbound(conntrack_t *ct, uint32_t client_ip,
                                         uint16_t client_port,
                                         uint32_t server_ip,
                                         uint16_t server_port,
                                         conntrack_entry_t *out) {
    (void)ct; (void)client_ip; (void)client_port; (void)server_ip;
    (void)server_port; (void)out;
    return ERR_NOT_FOUND;
}

error_t conntrack_track_direct_tcp(conntrack_t *ct,
                                   const conntrack_direct_tcp_flow_t *flow) {
    (void)ct; (void)flow;
    return ERR_OK;
}

error_t conntrack_track_tcp_proxy(conntrack_t *ct,
                                  const conntrack_tcp_proxy_flow_t *flow,
                                  uint16_t *relay_src_port_out) {
    (void)ct;
    if (relay_src_port_out) *relay_src_port_out = flow ? flow->client_port : 0;
    return ERR_OK;
}

error_t conntrack_track_udp_proxy(conntrack_t *ct,
                                  const conntrack_udp_proxy_flow_t *flow) {
    (void)ct; (void)flow;
    return ERR_OK;
}

error_t conntrack_track_tcp_dns(conntrack_t *ct,
                                const conntrack_tcp_dns_flow_t *flow) {
    (void)ct; (void)flow;
    return ERR_OK;
}

void conntrack_touch_direct_tcp(conntrack_t *ct, const conntrack_entry_t *entry) {
    (void)ct; (void)entry;
}

void conntrack_touch_tcp_proxy_outbound(conntrack_t *ct,
                                        const conntrack_entry_t *entry) {
    (void)ct; (void)entry;
}

void conntrack_touch_tcp_proxy_return(conntrack_t *ct,
                                      const conntrack_entry_t *entry) {
    (void)ct; (void)entry;
}

void conntrack_touch_udp_proxy_outbound(conntrack_t *ct,
                                        const conntrack_entry_t *entry) {
    (void)ct; (void)entry;
}

void conntrack_touch_udp_proxy_return(conntrack_t *ct,
                                      const conntrack_entry_t *entry) {
    (void)ct; (void)entry;
}

static void test_start_registers_one_reader_per_adapter(void) {
    ndisapi_engine_t engine;
    app_config_t config;
    conntrack_t conntrack;
    proc_lookup_t proc_lookup;
    dns_hijack_t dns_hijack;

    memset(&engine, 0, sizeof(engine));
    memset(&config, 0, sizeof(config));
    memset(&conntrack, 0, sizeof(conntrack));
    memset(&proc_lookup, 0, sizeof(proc_lookup));
    memset(&dns_hijack, 0, sizeof(dns_hijack));
    reset_test_state();

    config.policy.default_decision = RULE_DECISION_DIRECT;
    config.bypass.private_ips = 0;
    config.bypass.multicast = 0;
    config.bypass.broadcast = 0;
    dns_hijack.enabled = 0;

    if (ndisapi_start(&engine, &config, &conntrack, &proc_lookup, &dns_hijack,
                      40000, 40001) != ERR_OK) {
        fprintf(stderr, "FAIL ndisapi_start failed\n");
        failures++;
        return;
    }

    check_int("adapter count", (int)engine.adapter_count, 2);
    check_int("per-adapter packet events", packet_event_count, 2);
    check_handle("adapter event 0", packet_event_adapters[0], adapter_a);
    check_handle("adapter event 1", packet_event_adapters[1], adapter_b);
    check_handle_not_equal("distinct packet events", packet_events[0], packet_events[1]);
    check_int("flow worker count", (int)engine.flow_worker_count,
              (int)ndisapi_flow_worker_count_for_cpu(4));
    check_int("adapter reader and worker threads",
              g_test_windows_create_thread_count,
              2 + (int)engine.flow_worker_count + NDISAPI_SENDER_COUNT + 1);
    check_int("adapter modes", adapter_mode_count, 2);
    check_int("adapter change event registered", adapter_change_event_count, 1);

    engine_to_stop_after_read = &engine;
    if (!run_captured_thread(&engine.readers[0])) {
        fprintf(stderr, "FAIL adapter reader thread not captured\n");
        failures++;
    }
    for (DWORD i = 0; i < engine.flow_worker_count; i++) {
        if (!run_captured_thread(&engine.flow_workers[i])) {
            fprintf(stderr, "FAIL flow worker thread %lu not captured\n",
                    (unsigned long)i);
            failures++;
        }
    }
    check_int("MSTCP not sent before sender drain", mstcp_send_call_count, 0);
    for (DWORD i = 0; i < NDISAPI_SENDER_COUNT; i++) {
        if (!run_captured_thread(&engine.senders[i])) {
            fprintf(stderr, "FAIL sender thread %lu not captured\n",
                    (unsigned long)i);
            failures++;
        }
    }

    check_int("ReadPackets calls", read_packets_count, 1);
    check_int("ReadPacketsUnsorted calls", read_packets_unsorted_count, 0);
    check_handle("ReadPackets adapter", read_packets_adapters[0], adapter_a);
    check_int("ReadPackets batch", (int)read_packets_numbers[0], NDISAPI_BATCH_SIZE);
    check_int("MSTCP adapter-specific send calls", mstcp_send_call_count, 1);
    check_handle("MSTCP adapter-specific handle", mstcp_send_adapters[0], adapter_a);
    check_int("MSTCP adapter-specific batch", (int)mstcp_send_numbers[0], 1);
    check_int("MSTCP unsorted send count", mstcp_unsorted_send_count, 0);
    check_int("packets recv counter", (int)engine.counters.packets_recv, 1);
    check_int("packets sent counter", (int)engine.counters.packets_sent, 1);
    check_int("packet pool free after reader",
              (int)engine.packet_pool.free_count,
              (int)engine.packet_pool.capacity);

    ndisapi_stop(&engine);
}

static void test_adapter_change_marks_restart_required(void) {
    ndisapi_engine_t engine;
    app_config_t config;
    conntrack_t conntrack;
    proc_lookup_t proc_lookup;
    dns_hijack_t dns_hijack;
    ndisapi_counters_t counters;

    memset(&engine, 0, sizeof(engine));
    memset(&config, 0, sizeof(config));
    memset(&conntrack, 0, sizeof(conntrack));
    memset(&proc_lookup, 0, sizeof(proc_lookup));
    memset(&dns_hijack, 0, sizeof(dns_hijack));
    reset_test_state();

    config.policy.default_decision = RULE_DECISION_DIRECT;
    dns_hijack.enabled = 0;

    if (ndisapi_start(&engine, &config, &conntrack, &proc_lookup, &dns_hijack,
                      40000, 40001) != ERR_OK) {
        fprintf(stderr, "FAIL ndisapi_start failed\n");
        failures++;
        return;
    }

    log_capture_enabled = 1;
    if (!run_captured_thread(&engine)) {
        fprintf(stderr, "FAIL adapter monitor thread not captured\n");
        failures++;
    }

    check_int("restart required flag", engine.adapter_restart_required, 1);
    check_int("restart required counter",
              (int)engine.counters.adapter_restart_required, 1);
    check_contains("restart required log", log_last_message, "restart required");

    ndisapi_snapshot_counters(&engine, &counters);
    check_int("restart required snapshot",
              (int)counters.adapter_restart_required, 1);
    check_int("restart required counter reset",
              (int)engine.counters.adapter_restart_required, 0);

    ndisapi_stop(&engine);
}

static void test_stop_releases_lifecycle_resources_and_is_repeatable(void) {
    ndisapi_engine_t engine;
    app_config_t config;
    conntrack_t conntrack;
    proc_lookup_t proc_lookup;
    dns_hijack_t dns_hijack;
    int set_event_before_stop;

    memset(&engine, 0, sizeof(engine));
    memset(&config, 0, sizeof(config));
    memset(&conntrack, 0, sizeof(conntrack));
    memset(&proc_lookup, 0, sizeof(proc_lookup));
    memset(&dns_hijack, 0, sizeof(dns_hijack));
    reset_test_state();

    config.policy.default_decision = RULE_DECISION_DIRECT;
    dns_hijack.enabled = 0;

    if (ndisapi_start(&engine, &config, &conntrack, &proc_lookup, &dns_hijack,
                      40000, 40001) != ERR_OK) {
        fprintf(stderr, "FAIL ndisapi_start failed\n");
        failures++;
        return;
    }

    set_event_before_stop = g_test_windows_set_event_count;
    ndisapi_stop(&engine);

    check_int("adapter mode reset count", adapter_mode_reset_count, 2);
    check_int("packet event release count", packet_event_release_count, 2);
    check_int("stop wakes blocked handles",
              g_test_windows_set_event_count > set_event_before_stop, 1);
    check_int("packet pool destroyed", engine.packet_pool.capacity, 0);
    check_handle("driver closed", engine.driver_handle, INVALID_HANDLE_VALUE);

    ndisapi_stop(&engine);
    check_int("repeat stop keeps packet pool destroyed",
              engine.packet_pool.capacity, 0);
    check_handle("repeat stop keeps driver closed",
                 engine.driver_handle, INVALID_HANDLE_VALUE);
}

static void test_sender_batches_and_releases_packet_blocks(void) {
    ndisapi_engine_t engine;
    app_config_t config;
    conntrack_t conntrack;
    proc_lookup_t proc_lookup;
    dns_hijack_t dns_hijack;
    ndisapi_packet_block_t *a;
    ndisapi_packet_block_t *b;
    ndisapi_send_item_t items[2];

    memset(&engine, 0, sizeof(engine));
    memset(&config, 0, sizeof(config));
    memset(&conntrack, 0, sizeof(conntrack));
    memset(&proc_lookup, 0, sizeof(proc_lookup));
    memset(&dns_hijack, 0, sizeof(dns_hijack));
    reset_test_state();

    config.policy.default_decision = RULE_DECISION_DIRECT;
    dns_hijack.enabled = 0;

    if (ndisapi_start(&engine, &config, &conntrack, &proc_lookup, &dns_hijack,
                      40000, 40001) != ERR_OK) {
        fprintf(stderr, "FAIL ndisapi_start failed\n");
        failures++;
        return;
    }

    clear_send_capture();

    a = ndisapi_packet_block_acquire(&engine.packet_pool, adapter_a, 0);
    b = ndisapi_packet_block_acquire(&engine.packet_pool, adapter_a, 0);
    if (!a || !b) {
        fprintf(stderr, "FAIL sender test packet block acquire failed\n");
        failures++;
        ndisapi_stop(&engine);
        return;
    }
    a->buffer.m_hAdapter = adapter_a;
    b->buffer.m_hAdapter = adapter_a;
    memset(items, 0, sizeof(items));
    items[0].buf = &a->buffer;
    items[0].block = a;
    items[1].buf = &b->buffer;
    items[1].block = b;

    if (!ndisapi_enqueue_send_batch_to_mstcp(&engine, items, 2)) {
        fprintf(stderr, "FAIL enqueue MSTCP send batch failed\n");
        failures++;
    }
    ndisapi_packet_block_release(a);
    ndisapi_packet_block_release(b);
    check_int("MSTCP sender queued count",
              (int)engine.senders[NDISAPI_SEND_TARGET_MSTCP].count, 2);

    engine.running = 0;
    if (!run_captured_thread(&engine.senders[NDISAPI_SEND_TARGET_MSTCP])) {
        fprintf(stderr, "FAIL MSTCP sender thread not captured\n");
        failures++;
    }

    check_int("MSTCP sender driver calls", mstcp_send_call_count, 1);
    check_int("MSTCP sender batch size", (int)mstcp_send_numbers[0], 2);
    check_int("MSTCP sender releases blocks",
              (int)engine.packet_pool.free_count,
              (int)engine.packet_pool.capacity);

    clear_send_capture();
    engine.counters.send_failures = 0;
    a = ndisapi_packet_block_acquire(&engine.packet_pool, adapter_a, 0);
    if (!a) {
        fprintf(stderr, "FAIL sender failure block acquire failed\n");
        failures++;
        ndisapi_stop(&engine);
        return;
    }
    a->buffer.m_hAdapter = adapter_a;
    memset(items, 0, sizeof(items));
    items[0].buf = &a->buffer;
    items[0].block = a;
    if (!ndisapi_enqueue_send_batch_to_adapter(&engine, items, 1)) {
        fprintf(stderr, "FAIL enqueue adapter send batch failed\n");
        failures++;
    }
    ndisapi_packet_block_release(a);
    adapter_fail_next = 1;
    if (!run_captured_thread(&engine.senders[NDISAPI_SEND_TARGET_ADAPTER])) {
        fprintf(stderr, "FAIL adapter sender thread not captured\n");
        failures++;
    }

    check_int("adapter sender driver calls", adapter_send_call_count, 1);
    check_int("adapter sender failure counter",
              (int)engine.counters.send_failures, 1);
    check_int("adapter sender releases failed block",
              (int)engine.packet_pool.free_count,
              (int)engine.packet_pool.capacity);

    ndisapi_stop(&engine);
}

static void test_flow_worker_sizing_and_affinity(void) {
    INTERMEDIATE_BUFFER forward;
    INTERMEDIATE_BUFFER reverse;
    INTERMEDIATE_BUFFER other_adapter;
    INTERMEDIATE_BUFFER other_flow;
    INTERMEDIATE_BUFFER non_ip_send;
    INTERMEDIATE_BUFFER non_ip_recv;
    uint64_t forward_hash;
    uint64_t reverse_hash;

    reset_test_state();
    memset(&non_ip_send, 0, sizeof(non_ip_send));
    memset(&non_ip_recv, 0, sizeof(non_ip_recv));

    check_int("worker count low clamp",
              (int)ndisapi_flow_worker_count_for_cpu(1), 2);
    check_int("worker count exact",
              (int)ndisapi_flow_worker_count_for_cpu(8), 8);
    check_int("worker count high clamp",
              (int)ndisapi_flow_worker_count_for_cpu(64), 16);

    fill_ipv4_udp_packet(&forward, adapter_a, PACKET_FLAG_ON_SEND,
                         0x0A000001U, 12345, 0x08080808U, 53);
    fill_ipv4_udp_packet(&reverse, adapter_a, PACKET_FLAG_ON_RECEIVE,
                         0x08080808U, 53, 0x0A000001U, 12345);
    fill_ipv4_udp_packet(&other_adapter, adapter_b, PACKET_FLAG_ON_RECEIVE,
                         0x08080808U, 53, 0x0A000001U, 12345);
    fill_ipv4_udp_packet(&other_flow, adapter_a, PACKET_FLAG_ON_SEND,
                         0x0A000002U, 12346, 0x08080808U, 53);

    forward_hash = ndisapi_packet_flow_hash(&forward);
    reverse_hash = ndisapi_packet_flow_hash(&reverse);
    check_int("same flow normalized hash", forward_hash == reverse_hash, 1);
    check_int("adapter separates hash",
              ndisapi_packet_flow_hash(&other_adapter) != forward_hash, 1);
    check_int("different flow hash differs",
              ndisapi_packet_flow_hash(&other_flow) != forward_hash, 1);

    non_ip_send.m_hAdapter = adapter_a;
    non_ip_send.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
    non_ip_send.m_Length = ETHER_HDR_LEN;
    non_ip_recv.m_hAdapter = adapter_a;
    non_ip_recv.m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    non_ip_recv.m_Length = ETHER_HDR_LEN;
    check_int("non-ip direction separates hash",
              ndisapi_packet_flow_hash(&non_ip_send) !=
              ndisapi_packet_flow_hash(&non_ip_recv), 1);
}

static void test_flow_worker_enqueue_timeout_drops_and_releases(void) {
    ndisapi_engine_t engine;
    ndisapi_flow_worker_t *worker;
    DWORD i;

    reset_test_state();
    memset(&engine, 0, sizeof(engine));
    engine.driver_handle = (HANDLE)0xD001;
    engine.flow_worker_count = 1;
    worker = &engine.flow_workers[0];
    worker->engine = &engine;
    worker->worker_index = 0;
    worker->work_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    InitializeSRWLock(&worker->lock);

    if (!ndisapi_packet_pool_init(&engine.packet_pool,
                                  NDISAPI_FLOW_QUEUE_DEPTH + 1)) {
        fprintf(stderr, "FAIL packet pool init failed\n");
        failures++;
        return;
    }

    for (i = 0; i < NDISAPI_FLOW_QUEUE_DEPTH; i++) {
        ndisapi_packet_block_t *block =
            ndisapi_packet_block_acquire(&engine.packet_pool, adapter_a, 0);
        if (!ndisapi_flow_worker_enqueue(&engine, block, 0)) {
            fprintf(stderr, "FAIL enqueue unexpectedly failed at %lu\n",
                    (unsigned long)i);
            failures++;
            break;
        }
    }

    {
        DWORD free_before;
        ndisapi_packet_block_t *extra =
            ndisapi_packet_block_acquire(&engine.packet_pool, adapter_a, 0);
        free_before = engine.packet_pool.free_count;
        if (ndisapi_flow_worker_enqueue(&engine, extra, 0)) {
            fprintf(stderr, "FAIL enqueue succeeded on full worker queue\n");
            failures++;
        }
        check_int("enqueue timeout counter",
                  (int)engine.counters.enqueue_timeouts, 1);
        check_int("enqueue timeout dropped counter",
                  (int)engine.counters.packets_dropped, 1);
        check_int("enqueue timeout releases block",
                  (int)engine.packet_pool.free_count, (int)(free_before + 1));
    }

    while (worker->count > 0) {
        ndisapi_packet_block_t *block = worker->queue[worker->head];
        worker->queue[worker->head] = NULL;
        worker->head = (worker->head + 1U) % NDISAPI_FLOW_QUEUE_DEPTH;
        worker->count--;
        ndisapi_packet_block_release(block);
    }
    CloseHandle(worker->work_event);
    ndisapi_packet_pool_destroy(&engine.packet_pool);
}

static void test_packet_pool_acquire_release_and_refcounts(void) {
    ndisapi_packet_pool_t pool;
    ndisapi_packet_block_t *a;
    ndisapi_packet_block_t *b;
    ndisapi_packet_block_t *none;

    reset_test_state();
    memset(&pool, 0, sizeof(pool));

    if (!ndisapi_packet_pool_init(&pool, 2)) {
        fprintf(stderr, "FAIL packet pool init failed\n");
        failures++;
        return;
    }

    check_int("packet pool capacity", (int)pool.capacity, 2);
    check_int("packet pool initial free", (int)pool.free_count, 2);

    a = ndisapi_packet_block_acquire(&pool, adapter_a, 0);
    b = ndisapi_packet_block_acquire(&pool, adapter_b, 1);
    none = ndisapi_packet_block_acquire(&pool, adapter_a, 0);

    if (!a || !b) {
        fprintf(stderr, "FAIL packet pool acquire returned null before exhaustion\n");
        failures++;
    }
    if (none) {
        fprintf(stderr, "FAIL packet pool acquire succeeded after exhaustion\n");
        failures++;
    }
    check_int("packet pool empty free", (int)pool.free_count, 0);
    if (a) {
        check_handle("packet block adapter", a->adapter_handle, adapter_a);
        check_handle("packet block buffer adapter", a->buffer.m_hAdapter, adapter_a);
        check_int("packet block ref", (int)a->ref_count, 1);
        ndisapi_packet_block_retain(a);
        check_int("packet block retained ref", (int)a->ref_count, 2);
        ndisapi_packet_block_release(a);
        check_int("packet block release keeps owned", (int)a->ref_count, 1);
        check_int("packet pool still empty after retained release",
                  (int)pool.free_count, 0);
        ndisapi_packet_block_release(a);
    }
    if (b) ndisapi_packet_block_release(b);

    check_int("packet pool free after releases", (int)pool.free_count, 2);
    ndisapi_packet_pool_destroy(&pool);
}

static void test_packet_pool_exhaustion_flushes_adapter_queue(void) {
    ndisapi_engine_t engine;
    ndisapi_packet_block_t *held;
    ndisapi_packet_block_t *blocked;

    reset_test_state();
    memset(&engine, 0, sizeof(engine));
    engine.driver_handle = (HANDLE)0xD001;
    log_capture_enabled = 1;

    if (!ndisapi_packet_pool_init(&engine.packet_pool, 1)) {
        fprintf(stderr, "FAIL packet pool init failed\n");
        failures++;
        return;
    }

    held = ndisapi_packet_block_acquire(&engine.packet_pool, adapter_a, 0);
    blocked = ndisapi_packet_block_acquire_or_flush(&engine, adapter_b, 1, 0);

    if (!held) {
        fprintf(stderr, "FAIL held packet block missing\n");
        failures++;
    }
    if (blocked) {
        fprintf(stderr, "FAIL exhausted packet pool returned a block\n");
        failures++;
    }

    check_int("pool exhaustion flush count", flush_adapter_queue_count, 1);
    check_handle("pool exhaustion flush adapter",
                 flush_adapter_queue_adapters[0], adapter_b);
    check_int("pool exhaustion counter", (int)engine.counters.pool_exhausted, 1);
    check_int("pool flush counter", (int)engine.counters.adapter_queue_flushes, 1);
    check_int("pool overload counter", (int)engine.counters.overload_drops, 1);
    check_int("pool dropped counter", (int)engine.counters.packets_dropped, 1);
    check_contains("pool exhaustion log adapter", log_last_message, "adapter=");

    if (held) ndisapi_packet_block_release(held);
    ndisapi_packet_pool_destroy(&engine.packet_pool);
}

static void test_driver_sends_are_grouped_by_adapter_and_target(void) {
    ndisapi_engine_t engine;
    INTERMEDIATE_BUFFER a1;
    INTERMEDIATE_BUFFER a2;
    INTERMEDIATE_BUFFER b1;
    PINTERMEDIATE_BUFFER bufs[3];

    reset_test_state();
    memset(&engine, 0, sizeof(engine));
    memset(&a1, 0, sizeof(a1));
    memset(&a2, 0, sizeof(a2));
    memset(&b1, 0, sizeof(b1));

    engine.driver_handle = (HANDLE)0xD001;
    a1.m_hAdapter = adapter_a;
    a2.m_hAdapter = adapter_a;
    b1.m_hAdapter = adapter_b;
    bufs[0] = &a1;
    bufs[1] = &b1;
    bufs[2] = &a2;

    if (!ndisapi_send_batch_to_mstcp(&engine, bufs, 3)) {
        fprintf(stderr, "FAIL grouped MSTCP send returned failure\n");
        failures++;
    }

    check_int("MSTCP grouped send calls", mstcp_send_call_count, 2);
    check_handle("MSTCP grouped adapter 0", mstcp_send_adapters[0], adapter_a);
    check_int("MSTCP grouped count 0", (int)mstcp_send_numbers[0], 2);
    check_handle("MSTCP grouped adapter 1", mstcp_send_adapters[1], adapter_b);
    check_int("MSTCP grouped count 1", (int)mstcp_send_numbers[1], 1);
    check_int("MSTCP grouped unsorted calls", mstcp_unsorted_send_count, 0);
    check_int("MSTCP grouped sent counter", (int)engine.counters.packets_sent, 3);

    mstcp_send_call_count = 0;
    adapter_send_call_count = 0;
    memset(mstcp_send_adapters, 0, sizeof(mstcp_send_adapters));
    memset(adapter_send_adapters, 0, sizeof(adapter_send_adapters));
    memset(mstcp_send_numbers, 0, sizeof(mstcp_send_numbers));
    memset(adapter_send_numbers, 0, sizeof(adapter_send_numbers));
    engine.counters.packets_sent = 0;

    if (!ndisapi_send_batch_to_adapter(&engine, bufs, 3)) {
        fprintf(stderr, "FAIL grouped adapter send returned failure\n");
        failures++;
    }

    check_int("adapter grouped send calls", adapter_send_call_count, 2);
    check_handle("adapter grouped adapter 0", adapter_send_adapters[0], adapter_a);
    check_int("adapter grouped count 0", (int)adapter_send_numbers[0], 2);
    check_handle("adapter grouped adapter 1", adapter_send_adapters[1], adapter_b);
    check_int("adapter grouped count 1", (int)adapter_send_numbers[1], 1);
    check_int("adapter grouped unsorted calls", adapter_unsorted_send_count, 0);
    check_int("adapter grouped sent counter", (int)engine.counters.packets_sent, 3);
}

static void test_synthetic_dns_response_uses_adapter_specific_mstcp_send(void) {
    ndisapi_engine_t engine;
    app_config_t config;
    conntrack_t conntrack;
    proc_lookup_t proc_lookup;
    dns_hijack_t dns_hijack;
    traffic_action_t action;
    uint8_t dns_payload[12];

    reset_test_state();
    memset(&engine, 0, sizeof(engine));
    memset(&config, 0, sizeof(config));
    memset(&conntrack, 0, sizeof(conntrack));
    memset(&proc_lookup, 0, sizeof(proc_lookup));
    memset(&dns_hijack, 0, sizeof(dns_hijack));
    memset(&action, 0, sizeof(action));
    memset(dns_payload, 0, sizeof(dns_payload));

    config.policy.default_decision = RULE_DECISION_DIRECT;
    dns_hijack.enabled = 0;

    if (ndisapi_start(&engine, &config, &conntrack, &proc_lookup, &dns_hijack,
                      40000, 40001) != ERR_OK) {
        fprintf(stderr, "FAIL ndisapi_start failed\n");
        failures++;
        return;
    }
    clear_send_capture();

    traffic_action_inject_dns_response(&action, dns_payload, sizeof(dns_payload),
                                       0x1234, htonl(0x08080808U), 53,
                                       htonl(0x0A000005U), 40000,
                                       adapter_b, "dns response");

    traffic_execute_action(&engine, &action);

    check_int("DNS response queued to MSTCP sender",
              (int)engine.senders[NDISAPI_SEND_TARGET_MSTCP].count, 1);
    engine.running = 0;
    if (!run_captured_thread(&engine.senders[NDISAPI_SEND_TARGET_MSTCP])) {
        fprintf(stderr, "FAIL MSTCP sender thread not captured\n");
        failures++;
    }

    check_int("DNS response MSTCP send calls", mstcp_send_call_count, 1);
    check_handle("DNS response adapter handle", mstcp_send_adapters[0], adapter_b);
    check_int("DNS response MSTCP batch", (int)mstcp_send_numbers[0], 1);
    check_int("DNS response unsorted send count", mstcp_unsorted_send_count, 0);

    ndisapi_stop(&engine);
}

static void test_partial_and_failed_sends_update_counters_and_logs(void) {
    ndisapi_engine_t engine;
    INTERMEDIATE_BUFFER a1;
    INTERMEDIATE_BUFFER a2;
    PINTERMEDIATE_BUFFER bufs[2];

    reset_test_state();
    memset(&engine, 0, sizeof(engine));
    memset(&a1, 0, sizeof(a1));
    memset(&a2, 0, sizeof(a2));
    engine.driver_handle = (HANDLE)0xD001;
    a1.m_hAdapter = adapter_a;
    a2.m_hAdapter = adapter_a;
    bufs[0] = &a1;
    bufs[1] = &a2;

    log_capture_enabled = 1;
    mstcp_partial_next = 1;
    if (ndisapi_send_batch_to_mstcp(&engine, bufs, 2)) {
        fprintf(stderr, "FAIL partial MSTCP send returned success\n");
        failures++;
    }
    check_int("partial MSTCP sent counter", (int)engine.counters.packets_sent, 1);
    check_int("partial MSTCP failure counter", (int)engine.counters.send_failures, 1);
    check_int("partial MSTCP log count", log_write_count, 1);
    check_contains("partial MSTCP log target", log_last_message, "MSTCP");
    check_contains("partial MSTCP log adapter", log_last_message, "adapter=");

    memset(log_last_message, 0, sizeof(log_last_message));
    log_write_count = 0;
    adapter_fail_next = 1;
    if (ndisapi_send_batch_to_adapter(&engine, bufs, 1)) {
        fprintf(stderr, "FAIL failed adapter send returned success\n");
        failures++;
    }
    check_int("failed adapter failure counter", (int)engine.counters.send_failures, 2);
    check_int("failed adapter log count", log_write_count, 1);
    check_contains("failed adapter log target", log_last_message, "ADAPTER");
    check_contains("failed adapter log adapter", log_last_message, "adapter=");
}

int main(void) {
    test_packet_pool_acquire_release_and_refcounts();
    test_packet_pool_exhaustion_flushes_adapter_queue();
    test_flow_worker_sizing_and_affinity();
    test_flow_worker_enqueue_timeout_drops_and_releases();
    test_start_registers_one_reader_per_adapter();
    test_adapter_change_marks_restart_required();
    test_stop_releases_lifecycle_resources_and_is_repeatable();
    test_sender_batches_and_releases_packet_blocks();
    test_driver_sends_are_grouped_by_adapter_and_target();
    test_synthetic_dns_response_uses_adapter_specific_mstcp_send();
    test_partial_and_failed_sends_update_counters_and_logs();

    if (failures > 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    fprintf(stderr, "all tests passed\n");
    return 0;
}
