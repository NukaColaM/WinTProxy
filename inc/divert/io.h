#ifndef WINTPROXY_DIVERT_IO_H
#define WINTPROXY_DIVERT_IO_H

#include "divert/adapter.h"
#include "windivert/windivert.h"

#ifdef __cplusplus
extern "C" {
#endif

void divert_counter_inc(volatile LONG64 *counter);
int  divert_send_packet(divert_engine_t *engine, const void *packet, UINT packet_len,
                         WINDIVERT_ADDRESS *addr, const char *context);
void divert_set_loopback_route(divert_engine_t *engine, WINDIVERT_ADDRESS *addr);
uint16_t divert_next_tcp_relay_src_port(divert_engine_t *engine);
void divert_count_drop(divert_engine_t *engine);
void divert_count_udp_forwarded(divert_engine_t *engine);

#ifdef __cplusplus
}
#endif

#endif
