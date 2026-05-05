#ifndef WINTPROXY_UTIL_H
#define WINTPROXY_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "constants.h"

#ifdef _WIN32
#include <winsock2.h>
#endif

#define LOOPBACK_ADDR WTP_IPV4_LOOPBACK

static inline void ip_to_str(uint32_t ip, char *buf, size_t len) {
    unsigned char *b = (unsigned char *)&ip;
    snprintf(buf, len, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static inline int safe_str_copy(char *dst, size_t dst_len, const char *src) {
    size_t src_len;
    if (!dst || dst_len == 0 || !src) return 0;

    src_len = strlen(src);
    if (src_len >= dst_len) {
        dst[0] = '\0';
        return 0;
    }

    memcpy(dst, src, src_len + 1);
    return 1;
}

static inline uint32_t ipv4_net_to_host(uint32_t ip) {
#ifdef _WIN32
    return ntohl(ip);
#else
    return ((ip & 0x000000FFU) << 24) |
           ((ip & 0x0000FF00U) << 8) |
           ((ip & 0x00FF0000U) >> 8) |
           ((ip & 0xFF000000U) >> 24);
#endif
}

#endif
