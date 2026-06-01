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


#endif
