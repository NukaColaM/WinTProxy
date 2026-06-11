#ifndef WINTPROXY_TEST_WINSOCK2_H
#define WINTPROXY_TEST_WINSOCK2_H

#include "windows.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>

typedef int SOCKET;

typedef unsigned long u_long;

#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

static inline int WSAGetLastError(void) {
    return 0;
}

static inline int closesocket(SOCKET s) {
    return close(s);
}

static inline int wintproxy_test_getsockname(SOCKET s, struct sockaddr *addr,
                                             int *addrlen) {
    socklen_t len = addrlen ? (socklen_t)*addrlen : 0;
    int rc = getsockname(s, addr, addrlen ? &len : NULL);
    if (addrlen) *addrlen = (int)len;
    return rc;
}

#define getsockname wintproxy_test_getsockname

#endif
