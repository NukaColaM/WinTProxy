#define FD_SETSIZE 512
#include "udp_relay.h"
#include "socks5.h"
#include "log.h"
#include "util.h"
#include <string.h>

#define UDP_BUF_SIZE WTP_UDP_BUFFER_SIZE

typedef struct {
    SOCKET   relay_sock;
    uint16_t client_port;
} udp_session_snapshot_t;

static void close_socket_if_valid(SOCKET *sock) {
    if (*sock != INVALID_SOCKET) {
        closesocket(*sock);
        *sock = INVALID_SOCKET;
    }
}

static void session_clear(udp_session_t *s) {
    s->active = 0;
    s->client_port = 0;
    s->ctrl_sock = INVALID_SOCKET;
    s->relay_sock = INVALID_SOCKET;
    s->last_activity = 0;
    s->last_retry = 0;
    memset(&s->relay_addr, 0, sizeof(s->relay_addr));
}

static void session_close(udp_session_t *s) {
    close_socket_if_valid(&s->ctrl_sock);
    close_socket_if_valid(&s->relay_sock);
    session_clear(s);
}

static udp_session_t *find_session(udp_relay_t *relay, uint16_t client_port) {
    for (int i = 0; i < UDP_SESSION_MAX; i++) {
        if (relay->sessions[i].active && relay->sessions[i].client_port == client_port) {
            return &relay->sessions[i];
        }
    }
    return NULL;
}

static udp_session_t *alloc_session(udp_relay_t *relay) {
    for (int i = 0; i < UDP_SESSION_MAX; i++) {
        if (!relay->sessions[i].active) return &relay->sessions[i];
    }

    {
        udp_session_t *oldest = NULL;
        for (int i = 0; i < UDP_SESSION_MAX; i++) {
            if (!oldest || relay->sessions[i].last_activity < oldest->last_activity) {
                oldest = &relay->sessions[i];
            }
        }

        if (oldest) {
            session_close(oldest);
        }

        return oldest;
    }
}

static int setup_session_sockets(udp_relay_t *relay, SOCKET *ctrl_out, SOCKET *udp_out,
                                 struct sockaddr_in *relay_addr_out) {
    SOCKET ctrl = INVALID_SOCKET;
    SOCKET udp_sock = INVALID_SOCKET;

    if (socks5_connect_to_proxy(&ctrl, relay->proxy->ip_addr, relay->proxy->port) != ERR_OK) {
        LOG_ERROR("UDP relay: failed to connect to SOCKS5 proxy");
        return -1;
    }

    if (socks5_udp_associate(ctrl, relay_addr_out) != ERR_OK) {
        LOG_ERROR("UDP relay: SOCKS5 UDP ASSOCIATE failed");
        close_socket_if_valid(&ctrl);
        return -1;
    }

    udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET) {
        close_socket_if_valid(&ctrl);
        return -1;
    }

    {
        u_long nonblock = 1;
        ioctlsocket(udp_sock, (long)FIONBIO, &nonblock);
    }

    *ctrl_out = ctrl;
    *udp_out = udp_sock;
    return 0;
}

static int check_ctrl_alive(SOCKET ctrl_sock) {
    u_long nonblock = 1;
    u_long block = 0;
    char tmp;
    int ret;

    if (ctrl_sock == INVALID_SOCKET) return 0;

    ioctlsocket(ctrl_sock, (long)FIONBIO, &nonblock);
    ret = recv(ctrl_sock, &tmp, 1, MSG_PEEK);
    ioctlsocket(ctrl_sock, (long)FIONBIO, &block);

    if (ret == 0) return 0;
    if (ret < 0 && WSAGetLastError() != WSAEWOULDBLOCK) return 0;
    return 1;
}

static void cleanup_sessions(udp_relay_t *relay) {
    uint64_t now = GetTickCount64();
    for (int i = 0; i < UDP_SESSION_MAX; i++) {
        udp_session_t *s = &relay->sessions[i];
        if (!s->active) continue;

        if ((now - s->last_activity) > (UDP_SESSION_TTL_SEC * 1000ULL)) {
            LOG_DEBUG("UDP relay: session expired for port %u", s->client_port);
            session_close(s);
        }
    }
}

static int snapshot_session(udp_relay_t *relay, uint16_t client_port, SOCKET *relay_sock,
                            struct sockaddr_in *relay_addr) {
    int found = 0;

    AcquireSRWLockShared(&relay->session_lock);
    {
        udp_session_t *s = find_session(relay, client_port);
        if (s && s->relay_sock != INVALID_SOCKET) {
            *relay_sock = s->relay_sock;
            *relay_addr = s->relay_addr;
            found = 1;
        }
    }
    ReleaseSRWLockShared(&relay->session_lock);

    return found;
}

static void update_session_activity(udp_relay_t *relay, uint16_t client_port, SOCKET relay_sock) {
    AcquireSRWLockExclusive(&relay->session_lock);
    {
        udp_session_t *s = find_session(relay, client_port);
        if (s && s->relay_sock == relay_sock) {
            s->last_activity = GetTickCount64();
        }
    }
    ReleaseSRWLockExclusive(&relay->session_lock);
}

static int ensure_session(udp_relay_t *relay, uint16_t client_port) {
    SOCKET ctrl_sock = INVALID_SOCKET;
    int had_session = 0;

    AcquireSRWLockShared(&relay->session_lock);
    {
        udp_session_t *s = find_session(relay, client_port);
        if (s) {
            ctrl_sock = s->ctrl_sock;
            had_session = 1;
        }
    }
    ReleaseSRWLockShared(&relay->session_lock);

    if (had_session && check_ctrl_alive(ctrl_sock)) {
        return 1;
    }

    if (had_session) {
        AcquireSRWLockExclusive(&relay->session_lock);
        {
            udp_session_t *s = find_session(relay, client_port);
            if (s && s->ctrl_sock == ctrl_sock) {
                session_close(s);
            }
        }
        ReleaseSRWLockExclusive(&relay->session_lock);
    }

    {
        SOCKET new_ctrl = INVALID_SOCKET;
        SOCKET new_udp = INVALID_SOCKET;
        struct sockaddr_in new_relay_addr;
        uint64_t now = GetTickCount64();

        memset(&new_relay_addr, 0, sizeof(new_relay_addr));
        if (setup_session_sockets(relay, &new_ctrl, &new_udp, &new_relay_addr) != 0) {
            return 0;
        }

        AcquireSRWLockExclusive(&relay->session_lock);
        {
            udp_session_t *s = find_session(relay, client_port);
            if (s) {
                session_close(s);
            }

            s = alloc_session(relay);
            if (!s) {
                ReleaseSRWLockExclusive(&relay->session_lock);
                close_socket_if_valid(&new_ctrl);
                close_socket_if_valid(&new_udp);
                return 0;
            }

            s->active = 1;
            s->client_port = client_port;
            s->ctrl_sock = new_ctrl;
            s->relay_sock = new_udp;
            s->relay_addr = new_relay_addr;
            s->last_activity = now;
            s->last_retry = now;
        }
        ReleaseSRWLockExclusive(&relay->session_lock);

        LOG_DEBUG("UDP relay: session created for port %u", client_port);
        return 1;
    }
}

static int snapshot_relay_sockets(udp_relay_t *relay, udp_session_snapshot_t *snapshots,
                                  int max_snapshots, fd_set *fds, int *max_fd) {
    int count = 0;

    AcquireSRWLockShared(&relay->session_lock);
    for (int i = 0; i < UDP_SESSION_MAX && count < max_snapshots; i++) {
        udp_session_t *s = &relay->sessions[i];
        if (s->active && s->relay_sock != INVALID_SOCKET) {
            snapshots[count].relay_sock = s->relay_sock;
            snapshots[count].client_port = s->client_port;
            FD_SET(s->relay_sock, fds);
            if ((int)s->relay_sock > *max_fd) *max_fd = (int)s->relay_sock;
            count++;
        }
    }
    ReleaseSRWLockShared(&relay->session_lock);

    return count;
}

static void handle_client_datagram(udp_relay_t *relay, uint8_t *recv_buf, int n,
                                   uint8_t *send_buf, int send_buf_len) {
    uint16_t client_port = (uint16_t)(((uint16_t)recv_buf[0] << 8) | (uint16_t)recv_buf[1]);
    uint8_t *udp_payload = recv_buf + 2;
    int udp_payload_len = n - 2;
    uint32_t orig_dst_ip;
    uint16_t orig_dst_port;
    SOCKET relay_sock = INVALID_SOCKET;
    struct sockaddr_in relay_addr;

    if (conntrack_get(relay->conntrack, client_port, 17, &orig_dst_ip, &orig_dst_port) != ERR_OK) {
        LOG_TRACE("UDP relay: no conntrack for port %u, dropping", client_port);
        return;
    }

    if (!ensure_session(relay, client_port)) {
        LOG_TRACE("UDP relay: no available SOCKS UDP session for port %u", client_port);
        return;
    }

    if (!snapshot_session(relay, client_port, &relay_sock, &relay_addr)) {
        return;
    }

    {
        int wrapped = socks5_udp_wrap(send_buf, send_buf_len,
            orig_dst_ip, orig_dst_port, udp_payload, udp_payload_len);
        if (wrapped > 0) {
            int sent = sendto(relay_sock, (char *)send_buf, wrapped, 0,
                              (struct sockaddr *)&relay_addr, sizeof(relay_addr));
            if (sent != SOCKET_ERROR) {
                char dst_str[16];
                update_session_activity(relay, client_port, relay_sock);
                ip_to_str(orig_dst_ip, dst_str, sizeof(dst_str));
                LOG_TRACE("UDP relay: forwarded %d bytes from :%u to %s:%u",
                    udp_payload_len, client_port, dst_str, orig_dst_port);
            }
        }
    }
}

static void handle_proxy_datagram(udp_relay_t *relay, udp_session_snapshot_t *snapshot,
                                  uint8_t *recv_buf) {
    struct sockaddr_in from;
    int from_len = sizeof(from);
    int n = recvfrom(snapshot->relay_sock, (char *)recv_buf, UDP_BUF_SIZE, 0,
                     (struct sockaddr *)&from, &from_len);
    if (n <= 0) return;

    {
        uint32_t src_ip;
        uint16_t src_port;
        const uint8_t *payload;
        int payload_len;

        if (socks5_udp_unwrap(recv_buf, n, &src_ip, &src_port, &payload, &payload_len) == ERR_OK) {
            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            dst.sin_port = htons(snapshot->client_port);

            if (sendto(relay->local_sock, (const char *)payload, payload_len, 0,
                       (struct sockaddr *)&dst, sizeof(dst)) != SOCKET_ERROR) {
                update_session_activity(relay, snapshot->client_port, snapshot->relay_sock);
            }
        }
    }
}

static DWORD WINAPI udp_relay_thread(LPVOID param) {
    udp_relay_t *relay = (udp_relay_t *)param;
    uint8_t recv_buf[UDP_BUF_SIZE];
    uint8_t send_buf[UDP_BUF_SIZE];
    udp_session_snapshot_t snapshots[UDP_SESSION_MAX];
    uint64_t last_cleanup = GetTickCount64();

    while (relay->running) {
        fd_set fds;
        SOCKET local_sock = relay->local_sock;
        int max_fd;
        int snapshot_count;
        struct timeval tv;
        int ret;

        if (local_sock == INVALID_SOCKET) break;

        max_fd = (int)local_sock;
        FD_ZERO(&fds);
        FD_SET(local_sock, &fds);
        snapshot_count = snapshot_relay_sockets(relay, snapshots, UDP_SESSION_MAX, &fds, &max_fd);

        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        ret = select(max_fd + 1, &fds, NULL, NULL, &tv);

        if (ret < 0) {
            if (!relay->running) break;
            continue;
        }

        if (FD_ISSET(local_sock, &fds)) {
            struct sockaddr_in client_addr;
            int addr_len = sizeof(client_addr);
            int n = recvfrom(local_sock, (char *)recv_buf, sizeof(recv_buf), 0,
                             (struct sockaddr *)&client_addr, &addr_len);
            if (n > 2) {
                handle_client_datagram(relay, recv_buf, n, send_buf, sizeof(send_buf));
            }
        }

        for (int i = 0; i < snapshot_count; i++) {
            if (FD_ISSET(snapshots[i].relay_sock, &fds)) {
                handle_proxy_datagram(relay, &snapshots[i], recv_buf);
            }
        }

        {
            uint64_t now = GetTickCount64();
            if ((now - last_cleanup) > 30000) {
                AcquireSRWLockExclusive(&relay->session_lock);
                cleanup_sessions(relay);
                ReleaseSRWLockExclusive(&relay->session_lock);
                last_cleanup = now;
            }
        }
    }

    return 0;
}

error_t udp_relay_start(udp_relay_t *relay, conntrack_t *conntrack, proxy_config_t *proxy) {
    memset(relay, 0, sizeof(*relay));
    relay->local_sock = INVALID_SOCKET;
    relay->conntrack = conntrack;
    relay->proxy = proxy;
    relay->running = 1;
    InitializeSRWLock(&relay->session_lock);

    for (int i = 0; i < UDP_SESSION_MAX; i++) {
        session_clear(&relay->sessions[i]);
    }

    relay->local_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (relay->local_sock == INVALID_SOCKET) {
        LOG_ERROR("UDP relay: socket() failed: %d", WSAGetLastError());
        relay->running = 0;
        return ERR_NETWORK;
    }

    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(UDP_RELAY_PORT);

        if (bind(relay->local_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            LOG_ERROR("UDP relay: bind failed on port %u: %d", UDP_RELAY_PORT, WSAGetLastError());
            close_socket_if_valid(&relay->local_sock);
            relay->running = 0;
            return ERR_NETWORK;
        }
    }

    {
        u_long nonblock = 1;
        ioctlsocket(relay->local_sock, (long)FIONBIO, &nonblock);
    }

    relay->thread = CreateThread(NULL, 0, udp_relay_thread, relay, 0, NULL);
    if (!relay->thread) {
        LOG_ERROR("UDP relay: failed to create thread");
        close_socket_if_valid(&relay->local_sock);
        relay->running = 0;
        return ERR_GENERIC;
    }

    LOG_INFO("UDP relay listening on 127.0.0.1:%u", UDP_RELAY_PORT);
    return ERR_OK;
}

void udp_relay_stop(udp_relay_t *relay) {
    relay->running = 0;
    close_socket_if_valid(&relay->local_sock);

    if (relay->thread) {
        WaitForSingleObject(relay->thread, 5000);
        CloseHandle(relay->thread);
        relay->thread = NULL;
    }

    AcquireSRWLockExclusive(&relay->session_lock);
    for (int i = 0; i < UDP_SESSION_MAX; i++) {
        if (relay->sessions[i].active) {
            session_close(&relay->sessions[i]);
        }
    }
    ReleaseSRWLockExclusive(&relay->session_lock);

    LOG_INFO("UDP relay stopped");
}
