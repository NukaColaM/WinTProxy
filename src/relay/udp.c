#define FD_SETSIZE 2048
#include "relay/udp.h"
#include "relay/socks5.h"
#include "app/log.h"
#include "core/util.h"
#include <mswsock.h>
#include <stdlib.h>
#include <string.h>

#define UDP_BUF_SIZE WTP_UDP_BUFFER_SIZE
#define UDP_SOCKET_BUFFER_BYTES (1024 * 1024)

typedef struct {
    SOCKET           relay_sock;
    struct sockaddr_in relay_addr;
    uint32_t         client_ip;
    uint16_t         client_port;
    int              session_index;
    uint32_t         generation;
} udp_session_snapshot_t;

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

static void tune_udp_socket(SOCKET sock) {
    int size = UDP_SOCKET_BUFFER_BYTES;
    DWORD no_reset = 1;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *)&size, sizeof(size));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char *)&size, sizeof(size));
    WSAIoctl(sock, SIO_UDP_CONNRESET, &no_reset, sizeof(no_reset), NULL, 0, NULL, NULL, NULL);
}

static error_t bind_udp_listener(udp_relay_t *relay) {
    struct sockaddr_in addr;
    int err;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(UDP_RELAY_PORT);

    if (bind(relay->local_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        err = WSAGetLastError();
        LOG_WARN("UDP relay: bind failed on preferred port %u: %d; trying an ephemeral port",
                 UDP_RELAY_PORT, err);
        addr.sin_port = 0;
        if (bind(relay->local_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            LOG_ERROR("UDP relay: bind failed on ephemeral loopback port: %d", WSAGetLastError());
            return ERR_NETWORK;
        }
    }

    {
        struct sockaddr_in local;
        int local_len = sizeof(local);
        if (getsockname(relay->local_sock, (struct sockaddr *)&local, &local_len) == SOCKET_ERROR) {
            LOG_ERROR("UDP relay: getsockname failed: %d", WSAGetLastError());
            return ERR_NETWORK;
        }
        relay->port = ntohs(local.sin_port);
    }

    return ERR_OK;
}

static int session_hash(udp_relay_t *relay, uint32_t client_ip, uint16_t client_port) {
    uint32_t x = client_ip ^ ((uint32_t)client_port * 2654435761U);
    x ^= x >> 16;
    return (int)(x % relay->bucket_count);
}

static int session_index(udp_relay_t *relay, udp_session_t *s) {
    return (int)(s - relay->sessions);
}

static void active_unlink(udp_relay_t *relay, udp_session_t *s) {
    int idx = session_index(relay, s);
    if (s->active_prev >= 0) relay->sessions[s->active_prev].active_next = s->active_next;
    else if (relay->active_head == idx) relay->active_head = s->active_next;
    if (s->active_next >= 0) relay->sessions[s->active_next].active_prev = s->active_prev;
    else if (relay->active_tail == idx) relay->active_tail = s->active_prev;
    s->active_prev = -1;
    s->active_next = -1;
}

static void active_append(udp_relay_t *relay, udp_session_t *s) {
    int idx = session_index(relay, s);
    s->active_prev = relay->active_tail;
    s->active_next = -1;
    if (relay->active_tail >= 0) relay->sessions[relay->active_tail].active_next = idx;
    else relay->active_head = idx;
    relay->active_tail = idx;
}

static void active_touch(udp_relay_t *relay, udp_session_t *s) {
    if (relay->active_tail == session_index(relay, s)) return;
    active_unlink(relay, s);
    active_append(relay, s);
}

static void session_clear(udp_session_t *s, int keep_generation) {
    uint32_t generation = s->generation;
    memset(s, 0, sizeof(*s));
    s->ctrl_sock = INVALID_SOCKET;
    s->relay_sock = INVALID_SOCKET;
    s->active_prev = -1;
    s->active_next = -1;
    s->next_index = -1;
    s->bucket = -1;
    if (keep_generation) s->generation = generation;
}

static void unlink_session(udp_relay_t *relay, udp_session_t *s) {
    int idx;
    int *cur;

    if (s->bucket < 0) return;

    idx = session_index(relay, s);
    cur = &relay->session_buckets[s->bucket];
    while (*cur >= 0) {
        if (*cur == idx) {
            *cur = relay->sessions[*cur].next_index;
            break;
        }
        cur = &relay->sessions[*cur].next_index;
    }
    s->bucket = -1;
    s->next_index = -1;
}

static void link_session(udp_relay_t *relay, udp_session_t *s) {
    int idx = session_index(relay, s);
    int bucket = session_hash(relay, s->client_ip, s->client_port);
    s->bucket = bucket;
    s->next_index = relay->session_buckets[bucket];
    relay->session_buckets[bucket] = idx;
    active_append(relay, s);
}

static void session_close(udp_relay_t *relay, udp_session_t *s, int count_eviction) {
    if (!s->active) return;
    unlink_session(relay, s);
    active_unlink(relay, s);
    close_socket_if_valid(&s->ctrl_sock);
    close_socket_if_valid(&s->relay_sock);
    s->generation++;
    session_clear(s, 1);
    InterlockedDecrement64(&relay->counters.active_sessions);
    if (count_eviction) counter_inc(&relay->counters.evicted_sessions);
}

static udp_session_t *find_session(udp_relay_t *relay, uint32_t client_ip, uint16_t client_port) {
    int idx = relay->session_buckets[session_hash(relay, client_ip, client_port)];
    while (idx >= 0) {
        udp_session_t *s = &relay->sessions[idx];
        if (s->active && s->client_ip == client_ip && s->client_port == client_port) return s;
        idx = s->next_index;
    }
    return NULL;
}

static udp_session_t *alloc_session(udp_relay_t *relay) {
    for (size_t i = 0; i < relay->session_capacity; i++) {
        if (!relay->sessions[i].active) return &relay->sessions[i];
    }

    if (relay->active_head >= 0) {
        udp_session_t *oldest = &relay->sessions[relay->active_head];
        session_close(relay, oldest, 1);
        return oldest;
    }
    return NULL;
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
    tune_udp_socket(udp_sock);

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

static void cleanup_idle_sessions(udp_relay_t *relay) {
    uint64_t now = GetTickCount64();
    while (relay->active_head >= 0) {
        udp_session_t *s = &relay->sessions[relay->active_head];
        if ((now - s->last_activity) <= (UDP_SESSION_TTL_SEC * 1000ULL)) break;
        LOG_TRACE("UDP relay: session expired for port %u", s->client_port);
        session_close(relay, s, 1);
    }
}

static int ensure_session(udp_relay_t *relay, uint32_t client_ip, uint16_t client_port) {
    SOCKET ctrl_sock = INVALID_SOCKET;
    uint32_t generation = 0;
    int had_session = 0;

    AcquireSRWLockShared(&relay->session_lock);
    {
        udp_session_t *s = find_session(relay, client_ip, client_port);
        if (s) {
            ctrl_sock = s->ctrl_sock;
            generation = s->generation;
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
            udp_session_t *s = find_session(relay, client_ip, client_port);
            if (s && s->generation == generation && s->ctrl_sock == ctrl_sock) {
                LOG_TRACE("UDP relay: session control closed for port %u", client_port);
                session_close(relay, s, 1);
            }
        }
        ReleaseSRWLockExclusive(&relay->session_lock);
    }

    {
        SOCKET new_ctrl = INVALID_SOCKET;
        SOCKET new_udp = INVALID_SOCKET;
        struct sockaddr_in new_relay_addr;
        udp_session_t *s;
        uint64_t now;

        memset(&new_relay_addr, 0, sizeof(new_relay_addr));
        if (setup_session_sockets(relay, &new_ctrl, &new_udp, &new_relay_addr) != 0) {
            return 0;
        }

        AcquireSRWLockExclusive(&relay->session_lock);
        s = find_session(relay, client_ip, client_port);
        if (s) {
            ReleaseSRWLockExclusive(&relay->session_lock);
            close_socket_if_valid(&new_ctrl);
            close_socket_if_valid(&new_udp);
            return 1;
        }

        s = alloc_session(relay);
        if (!s) {
            ReleaseSRWLockExclusive(&relay->session_lock);
            close_socket_if_valid(&new_ctrl);
            close_socket_if_valid(&new_udp);
            return 0;
        }

        now = GetTickCount64();
        s->active = 1;
        s->client_ip = client_ip;
        s->client_port = client_port;
        s->ctrl_sock = new_ctrl;
        s->relay_sock = new_udp;
        s->relay_addr = new_relay_addr;
        s->last_activity = now;
        s->last_retry = now;
        link_session(relay, s);
        counter_inc(&relay->counters.created_sessions);
        counter_inc(&relay->counters.active_sessions);
        ReleaseSRWLockExclusive(&relay->session_lock);

        LOG_TRACE("UDP relay: session created for port %u", client_port);
        return 1;
    }
}

static int snapshot_session(udp_relay_t *relay, uint32_t client_ip, uint16_t client_port,
                            udp_session_snapshot_t *snapshot) {
    int found = 0;

    AcquireSRWLockShared(&relay->session_lock);
    {
        udp_session_t *s = find_session(relay, client_ip, client_port);
        if (s && s->relay_sock != INVALID_SOCKET) {
            snapshot->relay_sock = s->relay_sock;
            snapshot->relay_addr = s->relay_addr;
            snapshot->client_ip = client_ip;
            snapshot->client_port = client_port;
            snapshot->session_index = session_index(relay, s);
            snapshot->generation = s->generation;
            found = 1;
        }
    }
    ReleaseSRWLockShared(&relay->session_lock);

    return found;
}

static void update_session_activity(udp_relay_t *relay, const udp_session_snapshot_t *snapshot) {
    AcquireSRWLockExclusive(&relay->session_lock);
    if (snapshot->session_index >= 0 && (size_t)snapshot->session_index < relay->session_capacity) {
        udp_session_t *s = &relay->sessions[snapshot->session_index];
        if (s->active && s->generation == snapshot->generation && s->relay_sock == snapshot->relay_sock) {
            s->last_activity = GetTickCount64();
            active_touch(relay, s);
        }
    }
    ReleaseSRWLockExclusive(&relay->session_lock);
}

static void close_failed_snapshot(udp_relay_t *relay, const udp_session_snapshot_t *snapshot) {
    AcquireSRWLockExclusive(&relay->session_lock);
    if (snapshot->session_index >= 0 && (size_t)snapshot->session_index < relay->session_capacity) {
        udp_session_t *s = &relay->sessions[snapshot->session_index];
        if (s->active && s->generation == snapshot->generation && s->relay_sock == snapshot->relay_sock) {
            session_close(relay, s, 1);
        }
    }
    ReleaseSRWLockExclusive(&relay->session_lock);
}

static int snapshot_relay_sockets(udp_relay_t *relay, udp_session_snapshot_t *snapshots,
                                  int max_snapshots, fd_set *fds, int *max_fd) {
    int count = 0;

    AcquireSRWLockShared(&relay->session_lock);
    for (int idx = relay->active_head; idx >= 0 && count < max_snapshots; idx = relay->sessions[idx].active_next) {
        udp_session_t *s = &relay->sessions[idx];
        if (s->active && s->relay_sock != INVALID_SOCKET) {
            snapshots[count].relay_sock = s->relay_sock;
            snapshots[count].relay_addr = s->relay_addr;
            snapshots[count].client_ip = s->client_ip;
            snapshots[count].client_port = s->client_port;
            snapshots[count].session_index = idx;
            snapshots[count].generation = s->generation;
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
    uint32_t client_ip = LOOPBACK_ADDR;
    uint16_t client_port;
    uint8_t *udp_payload;
    int udp_payload_len;
    uint32_t orig_dst_ip;
    uint16_t orig_dst_port;
    udp_session_snapshot_t snapshot;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.session_index = -1;

    if (n < 6) {
        counter_inc(&relay->counters.dropped_datagrams);
        return;
    }

    memcpy(&client_ip, recv_buf, 4);
    client_port = (uint16_t)(((uint16_t)recv_buf[4] << 8) | (uint16_t)recv_buf[5]);
    udp_payload = recv_buf + 6;
    udp_payload_len = n - 6;

    if (conntrack_get(relay->conntrack, client_ip, client_port, 17, &orig_dst_ip, &orig_dst_port) != ERR_OK) {
        LOG_PACKET("UDP relay: no conntrack for port %u, dropping", client_port);
        counter_inc(&relay->counters.dropped_datagrams);
        return;
    }

    if (!ensure_session(relay, client_ip, client_port) ||
        !snapshot_session(relay, client_ip, client_port, &snapshot)) {
        LOG_PACKET("UDP relay: no available SOCKS UDP session for port %u", client_port);
        counter_inc(&relay->counters.dropped_datagrams);
        return;
    }

    {
        int wrapped = socks5_udp_wrap(send_buf, send_buf_len,
            orig_dst_ip, orig_dst_port, udp_payload, udp_payload_len);
        if (wrapped > 0) {
            int sent;

            sent = sendto(snapshot.relay_sock, (char *)send_buf, wrapped, 0,
                          (struct sockaddr *)&snapshot.relay_addr, sizeof(snapshot.relay_addr));
            if (sent != SOCKET_ERROR) {
                char dst_str[16];
                update_session_activity(relay, &snapshot);
                counter_add(&relay->counters.bytes_up, udp_payload_len);
                ip_to_str(orig_dst_ip, dst_str, sizeof(dst_str));
                LOG_PACKET("UDP relay: forwarded %d bytes from :%u to %s:%u",
                    udp_payload_len, client_port, dst_str, orig_dst_port);
            } else {
                close_failed_snapshot(relay, &snapshot);
                counter_inc(&relay->counters.dropped_datagrams);
            }
        } else {
            counter_inc(&relay->counters.dropped_datagrams);
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
            dst.sin_addr.s_addr = LOOPBACK_ADDR;
            dst.sin_port = htons(snapshot->client_port);

            if (sendto(relay->local_sock, (const char *)payload, payload_len, 0,
                       (struct sockaddr *)&dst, sizeof(dst)) != SOCKET_ERROR) {
                update_session_activity(relay, snapshot);
                counter_add(&relay->counters.bytes_down, payload_len);
            } else {
                counter_inc(&relay->counters.dropped_datagrams);
            }
        }
    }
}

static DWORD WINAPI udp_relay_thread(LPVOID param) {
    udp_relay_t *relay = (udp_relay_t *)param;
    uint8_t *recv_buf = (uint8_t *)malloc(UDP_BUF_SIZE);
    uint8_t *send_buf = (uint8_t *)malloc(UDP_BUF_SIZE);
    udp_session_snapshot_t *snapshots =
        (udp_session_snapshot_t *)calloc(relay->session_capacity, sizeof(*snapshots));
    uint64_t last_cleanup = GetTickCount64();

    if (!recv_buf || !send_buf || !snapshots) {
        free(recv_buf);
        free(send_buf);
        free(snapshots);
        return 0;
    }

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
        snapshot_count = snapshot_relay_sockets(relay, snapshots, (int)relay->session_capacity, &fds, &max_fd);

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
            int n = recvfrom(local_sock, (char *)recv_buf, UDP_BUF_SIZE, 0,
                             (struct sockaddr *)&client_addr, &addr_len);
            if (n > 2) {
                handle_client_datagram(relay, recv_buf, n, send_buf, UDP_BUF_SIZE);
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
                cleanup_idle_sessions(relay);
                ReleaseSRWLockExclusive(&relay->session_lock);
                last_cleanup = now;
            }
        }
    }

    free(recv_buf);
    free(send_buf);
    free(snapshots);
    return 0;
}

error_t udp_relay_start(udp_relay_t *relay, conntrack_t *conntrack, proxy_config_t *proxy) {
    memset(relay, 0, sizeof(*relay));
    relay->local_sock = INVALID_SOCKET;
    relay->conntrack = conntrack;
    relay->proxy = proxy;
    relay->running = 1;
    relay->session_capacity = UDP_SESSION_MAX;
    relay->bucket_count = UDP_SESSION_BUCKETS;
    relay->active_head = -1;
    relay->active_tail = -1;
    InitializeSRWLock(&relay->session_lock);

    relay->sessions = (udp_session_t *)calloc(relay->session_capacity, sizeof(relay->sessions[0]));
    relay->session_buckets = (int *)malloc(relay->bucket_count * sizeof(relay->session_buckets[0]));
    if (!relay->sessions || !relay->session_buckets) {
        free(relay->sessions);
        free(relay->session_buckets);
        relay->sessions = NULL;
        relay->session_buckets = NULL;
        return ERR_MEMORY;
    }

    for (size_t i = 0; i < relay->bucket_count; i++) relay->session_buckets[i] = -1;
    for (size_t i = 0; i < relay->session_capacity; i++) session_clear(&relay->sessions[i], 0);

    relay->local_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (relay->local_sock == INVALID_SOCKET) {
        LOG_ERROR("UDP relay: socket() failed: %d", WSAGetLastError());
        udp_relay_stop(relay);
        return ERR_NETWORK;
    }
    tune_udp_socket(relay->local_sock);

    if (bind_udp_listener(relay) != ERR_OK) {
        udp_relay_stop(relay);
        return ERR_NETWORK;
    }

    {
        u_long nonblock = 1;
        ioctlsocket(relay->local_sock, (long)FIONBIO, &nonblock);
    }

    relay->thread = CreateThread(NULL, 0, udp_relay_thread, relay, 0, NULL);
    if (!relay->thread) {
        LOG_ERROR("UDP relay: failed to create thread");
        udp_relay_stop(relay);
        return ERR_GENERIC;
    }

    LOG_INFO("UDP relay listening on 127.0.0.1:%u with %u session slots",
             relay->port, (unsigned int)relay->session_capacity);
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

    if (relay->sessions) {
        AcquireSRWLockExclusive(&relay->session_lock);
        for (size_t i = 0; i < relay->session_capacity; i++) {
            session_close(relay, &relay->sessions[i], 0);
        }
        ReleaseSRWLockExclusive(&relay->session_lock);
    }

    free(relay->sessions);
    free(relay->session_buckets);
    relay->sessions = NULL;
    relay->session_buckets = NULL;
    relay->active_head = -1;
    relay->active_tail = -1;

    LOG_INFO("UDP relay stopped");
}

void udp_relay_snapshot_counters(udp_relay_t *relay, udp_relay_counters_t *out) {
    memset(out, 0, sizeof(*out));
    out->active_sessions = InterlockedCompareExchange64(&relay->counters.active_sessions, 0, 0);
    out->created_sessions = InterlockedExchange64(&relay->counters.created_sessions, 0);
    out->evicted_sessions = InterlockedExchange64(&relay->counters.evicted_sessions, 0);
    out->dropped_datagrams = InterlockedExchange64(&relay->counters.dropped_datagrams, 0);
    out->bytes_up = InterlockedExchange64(&relay->counters.bytes_up, 0);
    out->bytes_down = InterlockedExchange64(&relay->counters.bytes_down, 0);
}
