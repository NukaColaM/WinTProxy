#ifndef WINTPROXY_RELAY_SOCKS5_H
#define WINTPROXY_RELAY_SOCKS5_H

#include <stdint.h>
#include "core/common.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#define SOCKS5_VERSION      0x05
#define SOCKS5_AUTH_NONE    0x00
#define SOCKS5_CMD_CONNECT  0x01
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
#define SOCKS5_ATYP_IPV4   0x01
#define SOCKS5_RSV          0x00

#pragma pack(push, 1)
typedef struct {
    uint16_t rsv;
    uint8_t  frag;
    uint8_t  atyp;
    uint32_t dst_addr;
    uint16_t dst_port;
} socks5_udp_header_t;
#pragma pack(pop)

error_t socks5_connect_to_proxy(SOCKET *out_sock, uint32_t proxy_ip, uint16_t proxy_port);
error_t socks5_tcp_handshake(SOCKET sock, uint32_t dst_ip, uint16_t dst_port);
error_t socks5_udp_associate(SOCKET ctrl_sock, struct sockaddr_in *relay_addr);

int socks5_udp_wrap(uint8_t *buf, int buf_size, uint32_t dst_ip, uint16_t dst_port,
                    const uint8_t *payload, int payload_len);
error_t socks5_udp_unwrap(const uint8_t *buf, int buf_len, uint32_t *src_ip,
                          uint16_t *src_port, const uint8_t **payload, int *payload_len);

#endif
