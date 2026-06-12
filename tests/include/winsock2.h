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

#ifndef FIONBIO
#define FIONBIO 0x8004667EL
#endif

#ifndef MSG_PEEK
#define MSG_PEEK 0x2
#endif

#ifndef WSAEWOULDBLOCK
#define WSAEWOULDBLOCK 10035
#endif

static inline int WSAGetLastError(void) {
    return 0;
}

static inline int closesocket(SOCKET s) {
    return close(s);
}

#ifdef WINTPROXY_TEST_HOOKS
extern int g_test_winsock_ioctl_count;
#endif

static inline int ioctlsocket(SOCKET s, long cmd, u_long *argp) {
    (void)s;
    (void)cmd;
    (void)argp;
#ifdef WINTPROXY_TEST_HOOKS
    g_test_winsock_ioctl_count++;
#endif
    return 0;
}

static inline int WSAIoctl(SOCKET s, DWORD dwIoControlCode, void *lpvInBuffer,
                           DWORD cbInBuffer, void *lpvOutBuffer,
                           DWORD cbOutBuffer, DWORD *lpcbBytesReturned,
                           void *lpOverlapped, void *lpCompletionRoutine) {
    (void)s; (void)dwIoControlCode; (void)lpvInBuffer; (void)cbInBuffer;
    (void)lpvOutBuffer; (void)cbOutBuffer; (void)lpcbBytesReturned;
    (void)lpOverlapped; (void)lpCompletionRoutine;
    return 0;
}

static inline int wintproxy_test_getsockname(SOCKET s, struct sockaddr *addr,
                                             int *addrlen) {
    socklen_t len = addrlen ? (socklen_t)*addrlen : 0;
    int rc = getsockname(s, addr, addrlen ? &len : NULL);
    if (addrlen) *addrlen = (int)len;
    return rc;
}

#define getsockname wintproxy_test_getsockname

static inline int wintproxy_test_recvfrom(SOCKET s, char *buf, int len, int flags,
                                          struct sockaddr *from, int *fromlen) {
    socklen_t slen = fromlen ? (socklen_t)*fromlen : 0;
    ssize_t rc = recvfrom(s, buf, (size_t)len, flags, from,
                          fromlen ? &slen : NULL);
    if (fromlen) *fromlen = (int)slen;
    return (int)rc;
}

#define recvfrom wintproxy_test_recvfrom

static inline int wintproxy_test_getpeername(SOCKET s, struct sockaddr *addr,
                                             int *addrlen) {
    socklen_t len = addrlen ? (socklen_t)*addrlen : 0;
    int rc = getpeername(s, addr, addrlen ? &len : NULL);
    if (addrlen) *addrlen = (int)len;
    return rc;
}

#define getpeername wintproxy_test_getpeername

#endif
