#include "tcp_relay.h"
#include "socks5.h"
#include "log.h"
#include "util.h"
#include <mswsock.h>
#include <stdlib.h>
#include <string.h>

#define TCP_RELAY_BUF_SIZE  WTP_TCP_RELAY_BUFFER_SIZE
#define TCP_KEY_SHUTDOWN    ((ULONG_PTR)1)

typedef enum {
    TCP_IO_ACCEPT = 1,
    TCP_IO_CONNECT,
    TCP_IO_CLIENT_RECV,
    TCP_IO_PROXY_RECV,
    TCP_IO_CLIENT_SEND,
    TCP_IO_PROXY_SEND
} tcp_io_type_t;

typedef enum {
    TCP_STATE_CONNECTING = 1,
    TCP_STATE_HANDSHAKE_AUTH_SEND,
    TCP_STATE_HANDSHAKE_AUTH_RECV,
    TCP_STATE_HANDSHAKE_REQ_SEND,
    TCP_STATE_HANDSHAKE_RESP_RECV,
    TCP_STATE_RELAY,
    TCP_STATE_CLOSING
} tcp_conn_state_t;

typedef struct tcp_io_s {
    OVERLAPPED    ov;
    WSABUF        wsabuf;
    tcp_io_type_t type;
    int           pending;
    DWORD         used;
    DWORD         offset;
    DWORD         wanted;
    char          buf[TCP_RELAY_BUF_SIZE];
} tcp_io_t;

struct tcp_conn_s {
    tcp_relay_t      *relay;
    SOCKET            client;
    SOCKET            proxy;
    uint32_t          lookup_ip;
    uint32_t          lookup_dst_ip;
    uint16_t          lookup_dst_port;
    uint32_t          client_ip;
    uint16_t          client_port;
    uint16_t          orig_client_port;
    uint32_t          orig_dst_ip;
    uint16_t          orig_dst_port;
    tcp_conn_state_t  state;
    LONG              closing;
    LONG              refs;
    int               active_counted;
    int               client_read_closed;
    int               proxy_read_closed;
    uint64_t          bytes_up;
    uint64_t          bytes_down;
    char              dst_str[16];
    tcp_io_t          client_recv;
    tcp_io_t          proxy_recv;
    tcp_io_t          client_send;
    tcp_io_t          proxy_send;
    tcp_io_t          connect_io;
    tcp_conn_t       *next_free;
    tcp_conn_t       *prev_active;
    tcp_conn_t       *next_active;
};

static LPFN_CONNECTEX g_connect_ex = NULL;

static void counter_inc(volatile LONG64 *counter) {
    InterlockedIncrement64(counter);
}

static void counter_add(volatile LONG64 *counter, LONG64 value) {
    InterlockedAdd64(counter, value);
}

static void close_socket_if_valid(SOCKET *sock) {
    if (*sock != INVALID_SOCKET) {
        closesocket(*sock);
        *sock = INVALID_SOCKET;
    }
}

static void tcp_conn_touch_conntrack(tcp_conn_t *conn) {
    conntrack_touch_key(conn->relay->conntrack, conn->lookup_ip, conn->client_port,
                        conn->lookup_dst_ip, conn->lookup_dst_port, 6);
    conntrack_touch_key(conn->relay->conntrack, conn->client_ip, conn->orig_client_port,
                        conn->orig_dst_ip, conn->orig_dst_port, 6);
}

static void tcp_conn_release(tcp_conn_t *conn);

static void tcp_conn_add_ref(tcp_conn_t *conn) {
    InterlockedIncrement(&conn->refs);
}

static void tcp_io_prepare(tcp_io_t *io, tcp_io_type_t type) {
    memset(&io->ov, 0, sizeof(io->ov));
    io->wsabuf.buf = io->buf;
    io->wsabuf.len = sizeof(io->buf);
    io->type = type;
    io->pending = 0;
    io->used = 0;
    io->offset = 0;
    io->wanted = 0;
}

static int tcp_worker_count(void) {
    SYSTEM_INFO si;
    int n;
    GetSystemInfo(&si);
    n = (int)si.dwNumberOfProcessors;
    if (n < 2) n = 2;
    if (n > TCP_RELAY_WORKER_MAX) n = TCP_RELAY_WORKER_MAX;
    return n;
}

static error_t load_connect_ex(SOCKET sock) {
    GUID guid = WSAID_CONNECTEX;
    DWORD bytes = 0;
    if (g_connect_ex) return ERR_OK;
    if (WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid, sizeof(guid), &g_connect_ex, sizeof(g_connect_ex),
                 &bytes, NULL, NULL) == SOCKET_ERROR) {
        LOG_ERROR("TCP relay: failed to load ConnectEx: %d", WSAGetLastError());
        return ERR_NETWORK;
    }
    return ERR_OK;
}

static SOCKET tcp_overlapped_socket(void) {
    return WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
}

static error_t bind_tcp_listener(tcp_relay_t *relay) {
    struct sockaddr_in addr;
    int err;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(TCP_RELAY_PORT);

    if (bind(relay->listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        err = WSAGetLastError();
        LOG_WARN("TCP relay: bind failed on preferred port %u: %d; trying an ephemeral port",
                 TCP_RELAY_PORT, err);
        addr.sin_port = 0;
        if (bind(relay->listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            LOG_ERROR("TCP relay: bind failed on ephemeral loopback port: %d", WSAGetLastError());
            return ERR_NETWORK;
        }
    }

    {
        struct sockaddr_in local;
        int local_len = sizeof(local);
        if (getsockname(relay->listen_sock, (struct sockaddr *)&local, &local_len) == SOCKET_ERROR) {
            LOG_ERROR("TCP relay: getsockname failed: %d", WSAGetLastError());
            return ERR_NETWORK;
        }
        relay->port = ntohs(local.sin_port);
    }

    return ERR_OK;
}

static tcp_conn_t *tcp_conn_alloc(tcp_relay_t *relay) {
    tcp_conn_t *conn = NULL;
    AcquireSRWLockExclusive(&relay->conn_lock);
    conn = relay->free_list;
    if (conn) {
        relay->free_list = conn->next_free;
        memset(conn, 0, sizeof(*conn));
        conn->relay = relay;
        conn->client = INVALID_SOCKET;
        conn->proxy = INVALID_SOCKET;
        conn->refs = 1;
        conn->next_active = relay->active_list;
        if (relay->active_list) relay->active_list->prev_active = conn;
        relay->active_list = conn;
    }
    ReleaseSRWLockExclusive(&relay->conn_lock);
    return conn;
}

static void tcp_conn_free(tcp_conn_t *conn) {
    tcp_relay_t *relay = conn->relay;
    AcquireSRWLockExclusive(&relay->conn_lock);
    if (conn->prev_active) conn->prev_active->next_active = conn->next_active;
    else if (relay->active_list == conn) relay->active_list = conn->next_active;
    if (conn->next_active) conn->next_active->prev_active = conn->prev_active;
    conn->next_free = relay->free_list;
    relay->free_list = conn;
    ReleaseSRWLockExclusive(&relay->conn_lock);
}

static void tcp_conn_close(tcp_conn_t *conn) {
    tcp_relay_t *relay = conn->relay;
    if (InterlockedExchange(&conn->closing, 1) != 0) return;
    conn->state = TCP_STATE_CLOSING;
    close_socket_if_valid(&conn->client);
    close_socket_if_valid(&conn->proxy);
    if (conn->client_port) {
        conntrack_remove_key(relay->conntrack, conn->lookup_ip, conn->client_port,
                             conn->lookup_dst_ip, conn->lookup_dst_port, 6);
        conntrack_remove_key(relay->conntrack, conn->client_ip, conn->orig_client_port,
                             conn->orig_dst_ip, conn->orig_dst_port, 6);
    }
    tcp_conn_release(conn);
}

static void tcp_conn_release(tcp_conn_t *conn) {
    if (InterlockedDecrement(&conn->refs) == 0) {
        if (conn->active_counted) {
            counter_add(&conn->relay->counters.bytes_up, (LONG64)conn->bytes_up);
            counter_add(&conn->relay->counters.bytes_down, (LONG64)conn->bytes_down);
            InterlockedDecrement64(&conn->relay->counters.active_connections);
            LOG_TRACE("TCP relay: closed :%u -> %s:%u (up=%llu down=%llu bytes)",
                conn->client_port, conn->dst_str, conn->orig_dst_port,
                (unsigned long long)conn->bytes_up, (unsigned long long)conn->bytes_down);
        }
        tcp_conn_free(conn);
    }
}

static void tcp_conn_maybe_close_after_eof(tcp_conn_t *conn) {
    if (conn->client_read_closed && conn->proxy_read_closed &&
        !conn->client_send.pending && !conn->proxy_send.pending) {
        tcp_conn_close(conn);
    }
}

static int associate_socket(tcp_relay_t *relay, SOCKET sock, tcp_conn_t *conn) {
    if (CreateIoCompletionPort((HANDLE)sock, relay->iocp, (ULONG_PTR)conn, 0) == NULL) {
        LOG_WARN("TCP relay: CreateIoCompletionPort socket association failed: %lu", GetLastError());
        return 0;
    }
    return 1;
}

static int post_recv(tcp_conn_t *conn, tcp_io_t *io, SOCKET sock, tcp_io_type_t type) {
    DWORD flags = 0;
    DWORD bytes = 0;
    int ret;

    if (conn->closing || io->pending) return 0;
    tcp_io_prepare(io, type);
    io->pending = 1;
    tcp_conn_add_ref(conn);
    ret = WSARecv(sock, &io->wsabuf, 1, &bytes, &flags, &io->ov, NULL);
    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        io->pending = 0;
        tcp_conn_release(conn);
        return 0;
    }
    return 1;
}

static int post_recv_with_buffer(tcp_conn_t *conn, tcp_io_t *io, SOCKET sock,
                                 tcp_io_type_t type, DWORD offset, DWORD len) {
    DWORD flags = 0;
    DWORD bytes = 0;
    int ret;

    if (offset + len > sizeof(io->buf) || conn->closing || io->pending) return 0;
    memset(&io->ov, 0, sizeof(io->ov));
    io->type = type;
    io->wsabuf.buf = io->buf + offset;
    io->wsabuf.len = len;
    io->pending = 1;
    tcp_conn_add_ref(conn);
    ret = WSARecv(sock, &io->wsabuf, 1, &bytes, &flags, &io->ov, NULL);
    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        io->pending = 0;
        tcp_conn_release(conn);
        return 0;
    }
    return 1;
}

static int post_send(tcp_conn_t *conn, tcp_io_t *io, SOCKET sock, tcp_io_type_t type,
                     const void *data, DWORD len) {
    DWORD bytes = 0;
    int ret;

    if (conn->closing || io->pending || len > sizeof(io->buf)) return 0;
    tcp_io_prepare(io, type);
    memcpy(io->buf, data, len);
    io->used = len;
    io->wsabuf.len = len;
    io->pending = 1;
    tcp_conn_add_ref(conn);
    ret = WSASend(sock, &io->wsabuf, 1, &bytes, 0, &io->ov, NULL);
    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        io->pending = 0;
        tcp_conn_release(conn);
        return 0;
    }
    return 1;
}

static int post_send_remaining(tcp_conn_t *conn, tcp_io_t *io, SOCKET sock, tcp_io_type_t type) {
    DWORD bytes = 0;
    DWORD remain;
    int ret;

    if (conn->closing || io->pending || io->offset >= io->used) return 0;
    remain = io->used - io->offset;
    memset(&io->ov, 0, sizeof(io->ov));
    io->type = type;
    io->wsabuf.buf = io->buf + io->offset;
    io->wsabuf.len = remain;
    io->pending = 1;
    tcp_conn_add_ref(conn);
    ret = WSASend(sock, &io->wsabuf, 1, &bytes, 0, &io->ov, NULL);
    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        io->pending = 0;
        tcp_conn_release(conn);
        return 0;
    }
    return 1;
}

static int post_recv_exact(tcp_conn_t *conn, tcp_io_t *io, SOCKET sock, tcp_io_type_t type,
                           DWORD wanted) {
    DWORD flags = 0;
    DWORD bytes = 0;
    int ret;

    if (wanted > sizeof(io->buf) || conn->closing || io->pending) return 0;
    tcp_io_prepare(io, type);
    io->wanted = wanted;
    io->wsabuf.len = wanted;
    io->pending = 1;
    tcp_conn_add_ref(conn);
    ret = WSARecv(sock, &io->wsabuf, 1, &bytes, &flags, &io->ov, NULL);
    if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        io->pending = 0;
        tcp_conn_release(conn);
        return 0;
    }
    return 1;
}

static void start_relay_io(tcp_conn_t *conn) {
    conn->state = TCP_STATE_RELAY;
    LOG_TRACE("TCP relay: tunnel established :%u -> %s:%u",
              conn->client_port, conn->dst_str, conn->orig_dst_port);
    if (!post_recv(conn, &conn->client_recv, conn->client, TCP_IO_CLIENT_RECV)) tcp_conn_close(conn);
    if (!post_recv(conn, &conn->proxy_recv, conn->proxy, TCP_IO_PROXY_RECV)) tcp_conn_close(conn);
}

static void start_socks_handshake(tcp_conn_t *conn) {
    static const uint8_t auth_req[3] = { SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE };
    conn->state = TCP_STATE_HANDSHAKE_AUTH_SEND;
    if (!post_send(conn, &conn->proxy_send, conn->proxy, TCP_IO_PROXY_SEND,
                   auth_req, sizeof(auth_req))) {
        counter_inc(&conn->relay->counters.handshake_failures);
        tcp_conn_close(conn);
    }
}

static int post_proxy_connect(tcp_conn_t *conn) {
    struct sockaddr_in proxy_addr;
    struct sockaddr_in bind_addr;
    DWORD sent = 0;
    BOOL ok;

    conn->proxy = tcp_overlapped_socket();
    if (conn->proxy == INVALID_SOCKET) return 0;

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = 0;
    if (bind(conn->proxy, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
        return 0;
    }

    if (!associate_socket(conn->relay, conn->proxy, conn)) return 0;
    if (load_connect_ex(conn->proxy) != ERR_OK) return 0;

    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = conn->relay->proxy->ip_addr;
    proxy_addr.sin_port = htons(conn->relay->proxy->port);

    tcp_io_prepare(&conn->connect_io, TCP_IO_CONNECT);
    conn->connect_io.pending = 1;
    conn->state = TCP_STATE_CONNECTING;
    tcp_conn_add_ref(conn);
    ok = g_connect_ex(conn->proxy, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr),
                      NULL, 0, &sent, &conn->connect_io.ov);
    if (!ok && WSAGetLastError() != ERROR_IO_PENDING) {
        conn->connect_io.pending = 0;
        tcp_conn_release(conn);
        return 0;
    }
    return 1;
}

static void tcp_conn_start(tcp_relay_t *relay, SOCKET client) {
    tcp_conn_t *conn = tcp_conn_alloc(relay);
    struct sockaddr_in peer;
    int peer_len = sizeof(peer);
    int nodelay = 1;

    if (!conn) {
        counter_inc(&relay->counters.rejected_connections);
        closesocket(client);
        return;
    }

    conn->client = client;
    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
    if (getpeername(client, (struct sockaddr *)&peer, &peer_len) == SOCKET_ERROR) {
        tcp_conn_close(conn);
        return;
    }
    conn->client_ip = peer.sin_addr.s_addr;
    conn->client_port = ntohs(peer.sin_port);
    conn->active_counted = 1;
    counter_inc(&relay->counters.active_connections);

    LOG_PACKET("TCP relay: accepted connection, peer port=%u", conn->client_port);

    {
        conntrack_entry_t entry;
        if (conntrack_get_full_key(relay->conntrack, LOOPBACK_ADDR, conn->client_port,
                                   LOOPBACK_ADDR, relay->port, 6, &entry) == ERR_OK) {
            conn->lookup_ip = entry.key_src_ip;
        } else if (conntrack_get_full(relay->conntrack, conn->client_ip, conn->client_port, 6, &entry) == ERR_OK) {
            conn->lookup_ip = entry.key_src_ip;
        } else if (conntrack_get_full(relay->conntrack, LOOPBACK_ADDR, conn->client_port, 6, &entry) == ERR_OK) {
            conn->lookup_ip = entry.key_src_ip;
        } else {
            LOG_WARN("TCP relay: no conntrack entry for %s:%u",
                     inet_ntoa(peer.sin_addr), conn->client_port);
            counter_inc(&relay->counters.rejected_connections);
            tcp_conn_close(conn);
            return;
        }
        conn->lookup_dst_ip = entry.key_dst_ip;
        conn->lookup_dst_port = entry.key_dst_port;
        conn->client_ip = entry.src_ip;
        conn->orig_client_port = entry.client_port;
        conn->orig_dst_ip = entry.orig_dst_ip;
        conn->orig_dst_port = entry.orig_dst_port;
    }

    ip_to_str(conn->orig_dst_ip, conn->dst_str, sizeof(conn->dst_str));
    LOG_PACKET("TCP relay: port %u -> %s:%u, connecting to SOCKS5 proxy",
               conn->client_port, conn->dst_str, conn->orig_dst_port);

    if (!associate_socket(relay, client, conn) || !post_proxy_connect(conn)) {
        counter_inc(&relay->counters.connect_failures);
        tcp_conn_close(conn);
        return;
    }

    counter_inc(&relay->counters.accepted_connections);
}

static void on_proxy_send_complete(tcp_conn_t *conn, DWORD bytes) {
    tcp_io_t *io = &conn->proxy_send;
    io->pending = 0;
    io->offset += bytes;
    if (io->offset < io->used) {
        if (!post_send_remaining(conn, io, conn->proxy, TCP_IO_PROXY_SEND)) tcp_conn_close(conn);
        return;
    }

    if (conn->state == TCP_STATE_HANDSHAKE_AUTH_SEND) {
        conn->state = TCP_STATE_HANDSHAKE_AUTH_RECV;
        if (!post_recv_exact(conn, &conn->proxy_recv, conn->proxy, TCP_IO_PROXY_RECV, 2)) {
            counter_inc(&conn->relay->counters.handshake_failures);
            tcp_conn_close(conn);
        }
        return;
    }

    if (conn->state == TCP_STATE_HANDSHAKE_REQ_SEND) {
        conn->state = TCP_STATE_HANDSHAKE_RESP_RECV;
        if (!post_recv_exact(conn, &conn->proxy_recv, conn->proxy, TCP_IO_PROXY_RECV, 4)) {
            counter_inc(&conn->relay->counters.handshake_failures);
            tcp_conn_close(conn);
        }
        return;
    }

    if (conn->state == TCP_STATE_RELAY) {
        conn->bytes_up += io->used;
        if (!conn->client_read_closed) {
            if (!post_recv(conn, &conn->client_recv, conn->client, TCP_IO_CLIENT_RECV)) tcp_conn_close(conn);
        } else {
            tcp_conn_maybe_close_after_eof(conn);
        }
    }
}

static void on_client_send_complete(tcp_conn_t *conn, DWORD bytes) {
    tcp_io_t *io = &conn->client_send;
    io->pending = 0;
    io->offset += bytes;
    if (io->offset < io->used) {
        if (!post_send_remaining(conn, io, conn->client, TCP_IO_CLIENT_SEND)) tcp_conn_close(conn);
        return;
    }
    conn->bytes_down += io->used;
    if (!conn->proxy_read_closed) {
        if (!post_recv(conn, &conn->proxy_recv, conn->proxy, TCP_IO_PROXY_RECV)) tcp_conn_close(conn);
    } else {
        tcp_conn_maybe_close_after_eof(conn);
    }
}

static void on_proxy_recv_complete(tcp_conn_t *conn, DWORD bytes) {
    tcp_io_t *io = &conn->proxy_recv;
    io->pending = 0;

    if (bytes == 0) {
        if (conn->state == TCP_STATE_RELAY) {
            conn->proxy_read_closed = 1;
            shutdown(conn->client, SD_SEND);
            tcp_conn_maybe_close_after_eof(conn);
        } else {
            tcp_conn_close(conn);
        }
        return;
    }

    if (conn->state == TCP_STATE_HANDSHAKE_AUTH_RECV) {
        io->offset += bytes;
        if (io->offset < io->wanted) {
            if (!post_recv_with_buffer(conn, io, conn->proxy, TCP_IO_PROXY_RECV,
                                       io->offset, io->wanted - io->offset)) {
                counter_inc(&conn->relay->counters.handshake_failures);
                tcp_conn_close(conn);
            }
            return;
        }
        if (io->offset < 2 || (uint8_t)io->buf[0] != SOCKS5_VERSION || (uint8_t)io->buf[1] != SOCKS5_AUTH_NONE) {
            counter_inc(&conn->relay->counters.handshake_failures);
            tcp_conn_close(conn);
            return;
        }
        {
            uint8_t req[10] = {
                SOCKS5_VERSION, SOCKS5_CMD_CONNECT, SOCKS5_RSV, SOCKS5_ATYP_IPV4,
                0, 0, 0, 0, 0, 0
            };
            uint16_t port_n = htons(conn->orig_dst_port);
            memcpy(req + 4, &conn->orig_dst_ip, 4);
            memcpy(req + 8, &port_n, 2);
            conn->state = TCP_STATE_HANDSHAKE_REQ_SEND;
            if (!post_send(conn, &conn->proxy_send, conn->proxy, TCP_IO_PROXY_SEND, req, sizeof(req))) {
                counter_inc(&conn->relay->counters.handshake_failures);
                tcp_conn_close(conn);
            }
        }
        return;
    }

    if (conn->state == TCP_STATE_HANDSHAKE_RESP_RECV) {
        io->offset += bytes;
        if (io->offset < io->wanted) {
            if (!post_recv_with_buffer(conn, io, conn->proxy, TCP_IO_PROXY_RECV,
                                       io->offset, io->wanted - io->offset)) {
                counter_inc(&conn->relay->counters.handshake_failures);
                tcp_conn_close(conn);
            }
            return;
        }
        if (io->offset < 4 || (uint8_t)io->buf[0] != SOCKS5_VERSION || (uint8_t)io->buf[1] != 0x00) {
            counter_inc(&conn->relay->counters.handshake_failures);
            tcp_conn_close(conn);
            return;
        }
        if (io->wanted == 4) {
            uint8_t atyp = (uint8_t)io->buf[3];
            DWORD next_wanted;
            if (atyp == SOCKS5_ATYP_IPV4) {
                next_wanted = 10;
            } else if (atyp == 0x03) {
                next_wanted = 5;
            } else if (atyp == 0x04) {
                next_wanted = 22;
            } else {
                counter_inc(&conn->relay->counters.handshake_failures);
                tcp_conn_close(conn);
                return;
            }
            io->wanted = next_wanted;
            if (!post_recv_with_buffer(conn, io, conn->proxy, TCP_IO_PROXY_RECV,
                                       io->offset, io->wanted - io->offset)) {
                counter_inc(&conn->relay->counters.handshake_failures);
                tcp_conn_close(conn);
            }
            return;
        }
        if (io->wanted == 5 && (uint8_t)io->buf[3] == 0x03) {
            DWORD next_wanted = 5U + (DWORD)(uint8_t)io->buf[4] + 2U;
            if (next_wanted > sizeof(io->buf)) {
                counter_inc(&conn->relay->counters.handshake_failures);
                tcp_conn_close(conn);
                return;
            }
            io->wanted = next_wanted;
            if (!post_recv_with_buffer(conn, io, conn->proxy, TCP_IO_PROXY_RECV,
                                       io->offset, io->wanted - io->offset)) {
                counter_inc(&conn->relay->counters.handshake_failures);
                tcp_conn_close(conn);
            }
            return;
        }
        start_relay_io(conn);
        return;
    }

    if (conn->state == TCP_STATE_RELAY) {
        tcp_conn_touch_conntrack(conn);
        if (!post_send(conn, &conn->client_send, conn->client, TCP_IO_CLIENT_SEND, io->buf, bytes)) {
            tcp_conn_close(conn);
        }
    }
}

static void on_client_recv_complete(tcp_conn_t *conn, DWORD bytes) {
    tcp_io_t *io = &conn->client_recv;
    io->pending = 0;
    if (bytes == 0) {
        conn->client_read_closed = 1;
        shutdown(conn->proxy, SD_SEND);
        tcp_conn_maybe_close_after_eof(conn);
        return;
    }
    tcp_conn_touch_conntrack(conn);
    if (!post_send(conn, &conn->proxy_send, conn->proxy, TCP_IO_PROXY_SEND, io->buf, bytes)) {
        tcp_conn_close(conn);
    }
}

static void tcp_handle_completion(tcp_conn_t *conn, tcp_io_t *io, DWORD bytes, BOOL ok) {
    if (!ok || conn->closing) {
        io->pending = 0;
        tcp_conn_close(conn);
        tcp_conn_release(conn);
        return;
    }

    switch (io->type) {
    case TCP_IO_CONNECT:
        io->pending = 0;
        setsockopt(conn->proxy, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
        start_socks_handshake(conn);
        break;
    case TCP_IO_CLIENT_RECV:
        on_client_recv_complete(conn, bytes);
        break;
    case TCP_IO_PROXY_RECV:
        on_proxy_recv_complete(conn, bytes);
        break;
    case TCP_IO_CLIENT_SEND:
        on_client_send_complete(conn, bytes);
        break;
    case TCP_IO_PROXY_SEND:
        on_proxy_send_complete(conn, bytes);
        break;
    default:
        tcp_conn_close(conn);
        break;
    }

    tcp_conn_release(conn);
}

static DWORD WINAPI tcp_iocp_worker(LPVOID param) {
    tcp_relay_t *relay = (tcp_relay_t *)param;
    for (;;) {
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        OVERLAPPED *ov = NULL;
        BOOL ok = GetQueuedCompletionStatus(relay->iocp, &bytes, &key, &ov, INFINITE);
        if (key == TCP_KEY_SHUTDOWN) break;
        if (!ov || !key) continue;
        tcp_handle_completion((tcp_conn_t *)key, (tcp_io_t *)ov, bytes, ok);
    }
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
            Sleep(1);
            continue;
        }
        tcp_conn_start(relay, client);
    }
    return 0;
}

static void tcp_close_active(tcp_relay_t *relay) {
    tcp_conn_t **snapshot;
    size_t count = 0;

    snapshot = (tcp_conn_t **)calloc(relay->connection_capacity, sizeof(snapshot[0]));
    if (!snapshot) return;

    AcquireSRWLockShared(&relay->conn_lock);
    for (tcp_conn_t *c = relay->active_list; c && count < relay->connection_capacity; c = c->next_active) {
        tcp_conn_add_ref(c);
        snapshot[count++] = c;
    }
    ReleaseSRWLockShared(&relay->conn_lock);

    for (size_t i = 0; i < count; i++) {
        tcp_conn_close(snapshot[i]);
        tcp_conn_release(snapshot[i]);
    }
    free(snapshot);
}

static int tcp_wait_for_drain(tcp_relay_t *relay) {
    DWORD start = GetTickCount();
    while (InterlockedCompareExchange64(&relay->counters.active_connections, 0, 0) > 0) {
        if (GetTickCount() - start > 5000) return 0;
        Sleep(10);
    }
    return 1;
}

error_t tcp_relay_start(tcp_relay_t *relay, conntrack_t *conntrack, proxy_config_t *proxy) {
    memset(relay, 0, sizeof(*relay));
    relay->listen_sock = INVALID_SOCKET;
    relay->conntrack = conntrack;
    relay->proxy = proxy;
    relay->running = 1;
    relay->connection_capacity = TCP_RELAY_CONN_MAX;
    InitializeSRWLock(&relay->conn_lock);

    relay->connections = (tcp_conn_t *)calloc(relay->connection_capacity, sizeof(relay->connections[0]));
    if (!relay->connections) {
        LOG_ERROR("TCP relay: failed to allocate connection pool");
        return ERR_MEMORY;
    }
    for (size_t i = 0; i < relay->connection_capacity; i++) {
        relay->connections[i].client = INVALID_SOCKET;
        relay->connections[i].proxy = INVALID_SOCKET;
        relay->connections[i].next_free = relay->free_list;
        relay->free_list = &relay->connections[i];
    }

    relay->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!relay->iocp) {
        free(relay->connections);
        relay->connections = NULL;
        relay->free_list = NULL;
        return ERR_GENERIC;
    }

    relay->listen_sock = tcp_overlapped_socket();
    if (relay->listen_sock == INVALID_SOCKET) {
        LOG_ERROR("TCP relay: socket() failed: %d", WSAGetLastError());
        tcp_relay_stop(relay);
        return ERR_NETWORK;
    }

    {
        int reuse = 1;
        setsockopt(relay->listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));
    }

    if (bind_tcp_listener(relay) != ERR_OK || listen(relay->listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        if (relay->listen_sock != INVALID_SOCKET) {
            LOG_ERROR("TCP relay: listen failed: %d", WSAGetLastError());
        }
        tcp_relay_stop(relay);
        return ERR_NETWORK;
    }

    relay->worker_count = tcp_worker_count();
    for (int i = 0; i < relay->worker_count; i++) {
        relay->workers[i] = CreateThread(NULL, 0, tcp_iocp_worker, relay, 0, NULL);
        if (!relay->workers[i]) {
            LOG_ERROR("TCP relay: failed to create IOCP worker %d", i);
            tcp_relay_stop(relay);
            return ERR_GENERIC;
        }
    }

    relay->thread = CreateThread(NULL, 0, tcp_accept_thread, relay, 0, NULL);
    if (!relay->thread) {
        LOG_ERROR("TCP relay: failed to create accept thread");
        tcp_relay_stop(relay);
        return ERR_GENERIC;
    }

    LOG_INFO("TCP relay listening on 127.0.0.1:%u with %d IOCP workers and %u connection slots",
             relay->port, relay->worker_count, (unsigned int)relay->connection_capacity);
    return ERR_OK;
}

void tcp_relay_stop(tcp_relay_t *relay) {
    relay->running = 0;
    close_socket_if_valid(&relay->listen_sock);

    if (relay->thread) {
        WaitForSingleObject(relay->thread, 5000);
        CloseHandle(relay->thread);
        relay->thread = NULL;
    }

    tcp_close_active(relay);
    {
        int drained = tcp_wait_for_drain(relay);
        if (!drained) {
            LOG_WARN("TCP relay: timed out draining active IOCP connections; leaking pool until process exit");
        }
    }

    if (relay->iocp) {
        for (int i = 0; i < relay->worker_count; i++) {
            PostQueuedCompletionStatus(relay->iocp, 0, TCP_KEY_SHUTDOWN, NULL);
        }
    }

    for (int i = 0; i < relay->worker_count; i++) {
        if (relay->workers[i]) {
            WaitForSingleObject(relay->workers[i], 5000);
            CloseHandle(relay->workers[i]);
            relay->workers[i] = NULL;
        }
    }
    relay->worker_count = 0;

    if (relay->iocp) {
        CloseHandle(relay->iocp);
        relay->iocp = NULL;
    }

    if (InterlockedCompareExchange64(&relay->counters.active_connections, 0, 0) == 0) {
        free(relay->connections);
        relay->connections = NULL;
        relay->free_list = NULL;
        relay->active_list = NULL;
    }

    LOG_INFO("TCP relay stopped");
}

void tcp_relay_snapshot_counters(tcp_relay_t *relay, tcp_relay_counters_t *out) {
    memset(out, 0, sizeof(*out));
    out->active_connections = InterlockedCompareExchange64(&relay->counters.active_connections, 0, 0);
    out->accepted_connections = InterlockedExchange64(&relay->counters.accepted_connections, 0);
    out->rejected_connections = InterlockedExchange64(&relay->counters.rejected_connections, 0);
    out->connect_failures = InterlockedExchange64(&relay->counters.connect_failures, 0);
    out->handshake_failures = InterlockedExchange64(&relay->counters.handshake_failures, 0);
    out->bytes_up = InterlockedExchange64(&relay->counters.bytes_up, 0);
    out->bytes_down = InterlockedExchange64(&relay->counters.bytes_down, 0);
}
