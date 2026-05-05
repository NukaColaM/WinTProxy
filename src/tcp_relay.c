#include "tcp_relay.h"
#include "socks5.h"
#include "log.h"
#include "util.h"
#include <string.h>

#define TCP_RELAY_BUF_SIZE  65536

typedef struct {
    SOCKET          client_sock;
    conntrack_t    *conntrack;
    proxy_config_t *proxy;
    volatile int   *running;
} tcp_conn_ctx_t;

static DWORD WINAPI tcp_connection_handler(LPVOID param) {
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)param;
    SOCKET client = ctx->client_sock;
    SOCKET proxy_sock = INVALID_SOCKET;

    struct sockaddr_in peer;
    int peer_len = sizeof(peer);
    getpeername(client, (struct sockaddr *)&peer, &peer_len);
    uint16_t client_port = ntohs(peer.sin_port);

    LOG_TRACE("TCP relay: accepted connection, peer port=%u", client_port);

    uint32_t orig_dst_ip;
    uint16_t orig_dst_port;
    if (conntrack_get(ctx->conntrack, client_port, 6, &orig_dst_ip, &orig_dst_port) != ERR_OK) {
        LOG_WARN("TCP relay: no conntrack entry for port %u", client_port);
        closesocket(client);
        free(ctx);
        return 0;
    }

    char dst_str[16];
    ip_to_str(orig_dst_ip, dst_str, sizeof(dst_str));
    LOG_DEBUG("TCP relay: port %u -> %s:%u, connecting to SOCKS5 proxy", client_port, dst_str, orig_dst_port);

    if (socks5_connect_to_proxy(&proxy_sock, ctx->proxy->ip_addr, ctx->proxy->port) != ERR_OK) {
        LOG_ERROR("TCP relay: failed to connect to SOCKS5 proxy for :%u -> %s:%u",
            client_port, dst_str, orig_dst_port);
        closesocket(client);
        free(ctx);
        return 0;
    }

    LOG_TRACE("TCP relay: connected to SOCKS5, starting handshake for %s:%u", dst_str, orig_dst_port);

    if (socks5_tcp_handshake(proxy_sock, orig_dst_ip, orig_dst_port) != ERR_OK) {
        LOG_ERROR("TCP relay: SOCKS5 handshake failed for %s:%u", dst_str, orig_dst_port);
        closesocket(proxy_sock);
        closesocket(client);
        free(ctx);
        return 0;
    }

    LOG_INFO("TCP relay: tunnel established :%u -> %s:%u", client_port, dst_str, orig_dst_port);

    char buf[TCP_RELAY_BUF_SIZE];
    fd_set fds;
    struct timeval tv;
    uint64_t bytes_up = 0, bytes_down = 0;

    while (1) {
        if (!*ctx->running) break;

        FD_ZERO(&fds);
        FD_SET(client, &fds);
        FD_SET(proxy_sock, &fds);

        tv.tv_sec = 0;
        tv.tv_usec = 50000;

        int max_fd = (int)((client > proxy_sock) ? client : proxy_sock);
        int ret = select(max_fd + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) break;
        if (ret == 0) {
            conntrack_touch(ctx->conntrack, client_port, 6);
            continue;
        }

        if (FD_ISSET(client, &fds)) {
            int n = recv(client, buf, sizeof(buf), 0);
            if (n <= 0) break;
            bytes_up += n;
            int sent = 0;
            while (sent < n) {
                int s = send(proxy_sock, buf + sent, n - sent, 0);
                if (s <= 0) goto done;
                sent += s;
            }
        }

        if (FD_ISSET(proxy_sock, &fds)) {
            int n = recv(proxy_sock, buf, sizeof(buf), 0);
            if (n <= 0) break;
            bytes_down += n;
            int sent = 0;
            while (sent < n) {
                int s = send(client, buf + sent, n - sent, 0);
                if (s <= 0) goto done;
                sent += s;
            }
        }
    }

done:
    closesocket(proxy_sock);
    closesocket(client);
    conntrack_remove(ctx->conntrack, client_port, 6);
    LOG_INFO("TCP relay: closed :%u -> %s:%u (up=%llu down=%llu bytes)",
        client_port, dst_str, orig_dst_port,
        (unsigned long long)bytes_up, (unsigned long long)bytes_down);
    free(ctx);
    return 0;
}

static DWORD WINAPI tcp_accept_thread(LPVOID param) {
    tcp_relay_t *relay = (tcp_relay_t *)param;

    while (relay->running) {
        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);

        SOCKET client = accept(relay->listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client == INVALID_SOCKET) {
            if (!relay->running) break;
            continue;
        }

        int timeout = 30000;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

        int nodelay = 1;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));

        tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)calloc(1, sizeof(tcp_conn_ctx_t));
        if (!ctx) { closesocket(client); continue; }
        ctx->client_sock = client;
        ctx->conntrack = relay->conntrack;
        ctx->proxy = relay->proxy;
        ctx->running = &relay->running;

        HANDLE th = CreateThread(NULL, 0, tcp_connection_handler, ctx, 0, NULL);
        if (th) {
            CloseHandle(th);
        } else {
            closesocket(client);
            free(ctx);
        }
    }

    return 0;
}

error_t tcp_relay_start(tcp_relay_t *relay, conntrack_t *conntrack, proxy_config_t *proxy) {
    memset(relay, 0, sizeof(*relay));
    relay->conntrack = conntrack;
    relay->proxy = proxy;
    relay->running = 1;

    relay->listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (relay->listen_sock == INVALID_SOCKET) {
        LOG_ERROR("TCP relay: socket() failed: %d", WSAGetLastError());
        return ERR_NETWORK;
    }

    int reuse = 1;
    setsockopt(relay->listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(TCP_RELAY_PORT);

    if (bind(relay->listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LOG_ERROR("TCP relay: bind failed on port %u: %d", TCP_RELAY_PORT, WSAGetLastError());
        closesocket(relay->listen_sock);
        return ERR_NETWORK;
    }

    if (listen(relay->listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        LOG_ERROR("TCP relay: listen failed: %d", WSAGetLastError());
        closesocket(relay->listen_sock);
        return ERR_NETWORK;
    }

    relay->thread = CreateThread(NULL, 0, tcp_accept_thread, relay, 0, NULL);
    if (!relay->thread) {
        LOG_ERROR("TCP relay: failed to create accept thread");
        closesocket(relay->listen_sock);
        return ERR_GENERIC;
    }

    LOG_INFO("TCP relay listening on 127.0.0.1:%u", TCP_RELAY_PORT);
    return ERR_OK;
}

void tcp_relay_stop(tcp_relay_t *relay) {
    relay->running = 0;
    if (relay->listen_sock != INVALID_SOCKET) {
        closesocket(relay->listen_sock);
        relay->listen_sock = INVALID_SOCKET;
    }
    if (relay->thread) {
        WaitForSingleObject(relay->thread, 5000);
        CloseHandle(relay->thread);
        relay->thread = NULL;
    }
    LOG_INFO("TCP relay stopped");
}
