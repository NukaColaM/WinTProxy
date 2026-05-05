#ifndef WINTPROXY_UTIL_H
#define WINTPROXY_UTIL_H

#include <stdint.h>
#include <stdio.h>

#define LOOPBACK_ADDR 0x0100007F

static inline void ip_to_str(uint32_t ip, char *buf, int len) {
    unsigned char *b = (unsigned char *)&ip;
    snprintf(buf, len, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

#endif
