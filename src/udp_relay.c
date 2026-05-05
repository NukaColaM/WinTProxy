#define FD_SETSIZE 512
#include "udp_relay.h"
#include "socks5.h"
#include "log.h"
#include "util.h"
#include <string.h>

#define UDP_BUF_SIZE 65536

static void session_clear(udp_session_t *s) {
    s->active = 0;
    s->client_port = 0;
    s->ctrl_sock = INVALID_SOCKET;
    s->relay_sock = INVALID_SOCKET;
    s->last_activity = 0;
    s->last_retry = 0;
    memset(&s->relay_addr, 0, sizeof(s->relay_addr));
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

    /* Evict oldest */
    udp_session_t *oldest = NULL;
    for (int i = 0; i < UDP_SESSION_MAX; i++) {
        if (!oldest || relay->sessions[i].last_activity < oldest->last_activity) {
            oldest = &relay->sessions[i];
        }
    }

    if (oldest) {
        if (oldest->ctrl_sock != INVALID_SOCKET) closesocket(oldest->ctrl_sock);
        if (oldest->relay_sock != INVALID_SOCKET) closesocket(oldest->relay_sock);
        session_clear(oldest);
    }

    return oldest;
}

static int setup_session(udp_relay_t *relay, udp_session_t *session, uint16_t client_port) {
    uint64_t now = GetTickCount64();

    if (session->active && session->client_port == client_port) {
        if ((now - session->last_retry) < UDP_RETRY_DELAY_MS) return -1;
    }

    session->last_retry = now;

    SOCKET ctrl = INVALID_SOCKET;
    if (socks5_connect_to_proxy(&ctrl, relay->proxy->ip_addr, relay->proxy->port) != ERR_OK) {
        LOG_ERROR("UDP relay: failed to connect to SOCKS5 proxy");
        return -1;
    }

    struct sockaddr_in relay_addr;
    if (socks5_udp_associate(ctrl, &relay_addr) != ERR_OK) {
        LOG_ERROR("UDP relay: SOCKS5 UDP ASSOCIATE failed");
        closesocket(ctrl);
        return -1;
    }

    SOCKET udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET) {
        closesocket(ctrl);
        return -1;
    }

    u_long nonblock = 1;
    ioctlsocket(udp_sock, FIONBIO, &nonblock);

    session->active = 1;
    session->client_port = client_port;
    session->ctrl_sock = ctrl;
    session->relay_sock = udp_sock;
    session->relay_addr = relay_addr;
    session->last_activity = now;

    LOG_DEBUG("UDP relay: session created for port %u", client_port);
    return 0;
}

static int check_ctrl_alive(udp_session_t *session) {
    u_long nonblock = 1;
    ioctlsocket(session->ctrl_sock, FIONBIO, &nonblock);
    char tmp;
    int ret = recv(session->ctrl_sock, &tmp, 1, MSG_PEEK);
    u_long block = 0;
    ioctlsocket(session->ctrl_sock, FIONBIO, &block);
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
            if (s->ctrl_sock != INVALID_SOCKET) closesocket(s->ctrl_sock);
            if (s->relay_sock != INVALID_SOCKET) closesocket(s->relay_sock);
            session_clear(s);
        }
    }
}

static DWORD WINAPI udp_relay_thread(LPVOID param) {
    udp_relay_t *relay = (udp_relay_t *)param;
    uint8_t recv_buf[UDP_BUF_SIZE];
    uint8_t send_buf[UDP_BUF_SIZE];
    uint64_t last_cleanup = GetTickCount64();

    while (relay->running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(relay->local_sock, &fds);

        int max_fd = (int)relay->local_sock;

        AcquireSRWLockShared(&relay->session_lock);
        for (int i = 0; i < UDP_SESSION_MAX; i++) {
            if (relay->sessions[i].active && relay->sessions[i].relay_sock != INVALID_SOCKET) {
                FD_SET(relay->sessions[i].relay_sock, &fds);
                if ((int)relay->sessions[i].relay_sock > max_fd)
                    max_fd = (int)relay->sessions[i].relay_sock;
            }
        }
        ReleaseSRWLockShared(&relay->session_lock);

        struct timeval tv = { 0, 100000 };
        int ret = select(max_fd + 1, &fds, NULL, NULL, &tv);

        if (ret < 0) {
            if (!relay->running) break;
            continue;
        }

        /* Check for incoming client data (framed: [2-byte client_port][payload]) */
        if (FD_ISSET(relay->local_sock, &fds)) {
            struct sockaddr_in client_addr;
            int addr_len = sizeof(client_addr);
            int n = recvfrom(relay->local_sock, (char *)recv_buf, sizeof(recv_buf), 0,
                            (struct sockaddr *)&client_addr, &addr_len);
            if (n > 2) {
                uint16_t client_port = (recv_buf[0] << 8) | recv_buf[1];
                uint8_t *udp_payload = recv_buf + 2;
                int udp_payload_len = n - 2;

                uint32_t orig_dst_ip;
                uint16_t orig_dst_port;
                if (conntrack_get(relay->conntrack, client_port, 17, &orig_dst_ip, &orig_dst_port) != ERR_OK) {
                    LOG_TRACE("UDP relay: no conntrack for port %u, dropping", client_port);
                    goto skip_send;
                }

                AcquireSRWLockExclusive(&relay->session_lock);
                udp_session_t *session = find_session(relay, client_port);
                if (!session || !check_ctrl_alive(session)) {
                    if (session) {
                        if (session->ctrl_sock != INVALID_SOCKET) closesocket(session->ctrl_sock);
                        if (session->relay_sock != INVALID_SOCKET) closesocket(session->relay_sock);
                        session_clear(session);
                    }
                    session = alloc_session(relay);
                    if (session && setup_session(relay, session, client_port) != 0) {
                        session = NULL;
                    }
                }
                ReleaseSRWLockExclusive(&relay->session_lock);

                if (session) {
                    int wrapped = socks5_udp_wrap(send_buf, sizeof(send_buf),
                        orig_dst_ip, orig_dst_port, udp_payload, udp_payload_len);
                    if (wrapped > 0) {
                        sendto(session->relay_sock, (char *)send_buf, wrapped, 0,
                              (struct sockaddr *)&session->relay_addr, sizeof(session->relay_addr));
                        session->last_activity = GetTickCount64();

                        char dst_str[16];
                        ip_to_str(orig_dst_ip, dst_str, sizeof(dst_str));
                        LOG_TRACE("UDP relay: forwarded %d bytes from :%u to %s:%u",
                            udp_payload_len, client_port, dst_str, orig_dst_port);
                    }
                }
            }
        }
skip_send:

        /* Check for incoming proxy data */
        AcquireSRWLockShared(&relay->session_lock);
        for (int i = 0; i < UDP_SESSION_MAX; i++) {
            udp_session_t *s = &relay->sessions[i];
            if (!s->active || s->relay_sock == INVALID_SOCKET) continue;

            if (FD_ISSET(s->relay_sock, &fds)) {
                struct sockaddr_in from;
                int from_len = sizeof(from);
                int n = recvfrom(s->relay_sock, (char *)recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr *)&from, &from_len);
                if (n > 0) {
                    uint32_t src_ip;
                    uint16_t src_port;
                    const uint8_t *payload;
                    int payload_len;

                    if (socks5_udp_unwrap(recv_buf, n, &src_ip, &src_port, &payload, &payload_len) == ERR_OK) {
                        struct sockaddr_in dst;
                        memset(&dst, 0, sizeof(dst));
                        dst.sin_family = AF_INET;
                        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                        dst.sin_port = htons(s->client_port);

                        sendto(relay->local_sock, (const char *)payload, payload_len, 0,
                              (struct sockaddr *)&dst, sizeof(dst));
                        s->last_activity = GetTickCount64();
                    }
                }
            }
        }
        ReleaseSRWLockShared(&relay->session_lock);

        /* Periodic cleanup */
        uint64_t now = GetTickCount64();
        if ((now - last_cleanup) > 30000) {
            AcquireSRWLockExclusive(&relay->session_lock);
            cleanup_sessions(relay);
            ReleaseSRWLockExclusive(&relay->session_lock);
            last_cleanup = now;
        }
    }

    return 0;
}

error_t udp_relay_start(udp_relay_t *relay, conntrack_t *conntrack, proxy_config_t *proxy) {
    memset(relay, 0, sizeof(*relay));
    relay->conntrack = conntrack;
    relay->proxy = proxy;
    relay->running = 1;
    InitializeSRWLock(&relay->session_lock);

    for (int i = 0; i < UDP_SESSION_MAX; i++) {
        relay->sessions[i].ctrl_sock = INVALID_SOCKET;
        relay->sessions[i].relay_sock = INVALID_SOCKET;
    }

    relay->local_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (relay->local_sock == INVALID_SOCKET) {
        LOG_ERROR("UDP relay: socket() failed: %d", WSAGetLastError());
        return ERR_NETWORK;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(UDP_RELAY_PORT);

    if (bind(relay->local_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LOG_ERROR("UDP relay: bind failed on port %u: %d", UDP_RELAY_PORT, WSAGetLastError());
        closesocket(relay->local_sock);
        return ERR_NETWORK;
    }

    u_long nonblock = 1;
    ioctlsocket(relay->local_sock, FIONBIO, &nonblock);

    relay->thread = CreateThread(NULL, 0, udp_relay_thread, relay, 0, NULL);
    if (!relay->thread) {
        LOG_ERROR("UDP relay: failed to create thread");
        closesocket(relay->local_sock);
        return ERR_GENERIC;
    }

    LOG_INFO("UDP relay listening on 127.0.0.1:%u", UDP_RELAY_PORT);
    return ERR_OK;
}

void udp_relay_stop(udp_relay_t *relay) {
    relay->running = 0;
    if (relay->local_sock != INVALID_SOCKET) {
        closesocket(relay->local_sock);
        relay->local_sock = INVALID_SOCKET;
    }
    if (relay->thread) {
        WaitForSingleObject(relay->thread, 5000);
        CloseHandle(relay->thread);
        relay->thread = NULL;
    }

    for (int i = 0; i < UDP_SESSION_MAX; i++) {
        if (relay->sessions[i].active) {
            if (relay->sessions[i].ctrl_sock != INVALID_SOCKET)
                closesocket(relay->sessions[i].ctrl_sock);
            if (relay->sessions[i].relay_sock != INVALID_SOCKET)
                closesocket(relay->sessions[i].relay_sock);
        }
    }

    LOG_INFO("UDP relay stopped");
}
