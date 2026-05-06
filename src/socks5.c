#include "socks5.h"
#include "log.h"
#include "util.h"
#include <string.h>

static int send_all(SOCKET sock, const void *buf, int len) {
    const char *p = (const char *)buf;
    int total = 0;
    while (total < len) {
        int n = send(sock, p + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

static int recv_all(SOCKET sock, void *buf, int len) {
    char *p = (char *)buf;
    int total = 0;
    while (total < len) {
        int n = recv(sock, p + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

error_t socks5_connect_to_proxy(SOCKET *out_sock, uint32_t proxy_ip, uint16_t proxy_port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        LOG_ERROR("socks5: socket() failed: %d", WSAGetLastError());
        return ERR_NETWORK;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = proxy_ip;
    addr.sin_port = htons(proxy_port);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LOG_ERROR("socks5: connect to proxy failed: %d", WSAGetLastError());
        closesocket(sock);
        return ERR_NETWORK;
    }

    int timeout = 10000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

    *out_sock = sock;
    return ERR_OK;
}

static error_t socks5_negotiate_auth(SOCKET sock) {
    uint8_t req[3] = { SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE };
    LOG_PACKET("socks5: sending auth [%02x %02x %02x]", req[0], req[1], req[2]);
    if (send_all(sock, req, sizeof(req)) < 0) {
        LOG_ERROR("socks5: failed to send auth negotiation");
        return ERR_NETWORK;
    }

    uint8_t resp[2];
    if (recv_all(sock, resp, sizeof(resp)) < 0) {
        LOG_ERROR("socks5: failed to receive auth response");
        return ERR_NETWORK;
    }

    LOG_PACKET("socks5: auth response [%02x %02x]", resp[0], resp[1]);

    if (resp[0] != SOCKS5_VERSION || resp[1] != SOCKS5_AUTH_NONE) {
        LOG_ERROR("socks5: auth rejected (ver=%02x, method=%02x)", resp[0], resp[1]);
        return ERR_PROTO;
    }

    return ERR_OK;
}

static error_t socks5_recv_response(SOCKET sock, uint8_t *atyp_out,
                                    uint32_t *bind_ip, uint16_t *bind_port) {
    uint8_t hdr[4];
    if (recv_all(sock, hdr, 4) < 0) return ERR_NETWORK;

    LOG_PACKET("socks5: response hdr [%02x %02x %02x %02x]", hdr[0], hdr[1], hdr[2], hdr[3]);

    if (hdr[0] != SOCKS5_VERSION) return ERR_PROTO;
    if (hdr[1] != 0x00) {
        LOG_ERROR("socks5: server returned error status %02x", hdr[1]);
        return ERR_PROTO;
    }

    uint8_t atyp = hdr[3];
    if (atyp_out) *atyp_out = atyp;

    if (atyp == 0x01) {
        uint8_t addr_port[6];
        if (recv_all(sock, addr_port, 6) < 0) return ERR_NETWORK;
        if (bind_ip) memcpy(bind_ip, addr_port, 4);
        if (bind_port) memcpy(bind_port, addr_port + 4, 2);
    } else if (atyp == 0x03) {
        uint8_t dlen;
        if (recv_all(sock, &dlen, 1) < 0) return ERR_NETWORK;
        uint8_t tmp[258];
        if (recv_all(sock, tmp, dlen + 2) < 0) return ERR_NETWORK;
        if (bind_ip) *bind_ip = 0;
        if (bind_port) memcpy(bind_port, tmp + dlen, 2);
    } else if (atyp == 0x04) {
        uint8_t tmp[18];
        if (recv_all(sock, tmp, 18) < 0) return ERR_NETWORK;
        if (bind_ip) *bind_ip = 0;
        if (bind_port) memcpy(bind_port, tmp + 16, 2);
    } else {
        return ERR_PROTO;
    }

    return ERR_OK;
}


error_t socks5_tcp_handshake(SOCKET sock, uint32_t dst_ip, uint16_t dst_port) {
    unsigned char *ib = (unsigned char *)&dst_ip;
    LOG_PACKET("socks5: CONNECT to %u.%u.%u.%u:%u", ib[0], ib[1], ib[2], ib[3], dst_port);

    if (socks5_negotiate_auth(sock) != ERR_OK) return ERR_PROTO;

    uint8_t req[10] = {
        SOCKS5_VERSION,
        SOCKS5_CMD_CONNECT,
        SOCKS5_RSV,
        SOCKS5_ATYP_IPV4,
        0, 0, 0, 0,
        0, 0
    };
    memcpy(req + 4, &dst_ip, 4);
    uint16_t port_n = htons(dst_port);
    memcpy(req + 8, &port_n, 2);

    if (send_all(sock, req, sizeof(req)) < 0) {
        LOG_ERROR("socks5: failed to send CONNECT request");
        return ERR_NETWORK;
    }

    if (socks5_recv_response(sock, NULL, NULL, NULL) != ERR_OK) {
        LOG_ERROR("socks5: CONNECT failed");
        return ERR_PROTO;
    }

    LOG_PACKET("socks5: CONNECT succeeded");
    return ERR_OK;
}

error_t socks5_udp_associate(SOCKET ctrl_sock, struct sockaddr_in *relay_addr) {
    if (socks5_negotiate_auth(ctrl_sock) != ERR_OK) return ERR_PROTO;

    uint8_t req[10] = {
        SOCKS5_VERSION,
        SOCKS5_CMD_UDP_ASSOCIATE,
        SOCKS5_RSV,
        SOCKS5_ATYP_IPV4,
        0, 0, 0, 0,
        0, 0
    };

    if (send_all(ctrl_sock, req, sizeof(req)) < 0) {
        LOG_ERROR("socks5: failed to send UDP ASSOCIATE request");
        return ERR_NETWORK;
    }

    uint32_t bind_ip = 0;
    uint16_t bind_port_n = 0;
    if (socks5_recv_response(ctrl_sock, NULL, &bind_ip, &bind_port_n) != ERR_OK) {
        LOG_ERROR("socks5: UDP ASSOCIATE failed");
        return ERR_PROTO;
    }

    memset(relay_addr, 0, sizeof(*relay_addr));
    relay_addr->sin_family = AF_INET;
    relay_addr->sin_addr.s_addr = bind_ip;
    relay_addr->sin_port = bind_port_n;

    /* If the proxy returns 0.0.0.0, use the proxy's own address */
    if (relay_addr->sin_addr.s_addr == 0) {
        struct sockaddr_in proxy_addr;
        int len = sizeof(proxy_addr);
        getpeername(ctrl_sock, (struct sockaddr *)&proxy_addr, &len);
        relay_addr->sin_addr.s_addr = proxy_addr.sin_addr.s_addr;
    }

    char relay_str[16];
    ip_to_str(relay_addr->sin_addr.s_addr, relay_str, sizeof(relay_str));
    LOG_PACKET("socks5: UDP ASSOCIATE relay at %s:%u",
        relay_str, ntohs(relay_addr->sin_port));
    return ERR_OK;
}

int socks5_udp_wrap(uint8_t *buf, int buf_size, uint32_t dst_ip, uint16_t dst_port,
                    const uint8_t *payload, int payload_len) {
    size_t header_size = sizeof(socks5_udp_header_t);
    size_t total;
    if (payload_len < 0 || buf_size < 0) return -1;
    total = header_size + (size_t)payload_len;
    if (total > (size_t)buf_size) return -1;

    socks5_udp_header_t hdr;
    hdr.rsv = 0;
    hdr.frag = 0;
    hdr.atyp = SOCKS5_ATYP_IPV4;
    hdr.dst_addr = dst_ip;
    hdr.dst_port = htons(dst_port);

    memcpy(buf, &hdr, header_size);
    memcpy(buf + header_size, payload, (size_t)payload_len);
    return (int)total;
}

error_t socks5_udp_unwrap(const uint8_t *buf, int buf_len, uint32_t *src_ip,
                          uint16_t *src_port, const uint8_t **payload, int *payload_len) {
    int header_size = sizeof(socks5_udp_header_t);
    if (buf_len < header_size) return ERR_PARAM;

    const socks5_udp_header_t *hdr = (const socks5_udp_header_t *)buf;
    if (hdr->atyp != SOCKS5_ATYP_IPV4) {
        LOG_WARN("socks5: unsupported UDP response ATYP: %02x", hdr->atyp);
        return ERR_PROTO;
    }

    if (src_ip) *src_ip = hdr->dst_addr;
    if (src_port) *src_port = ntohs(hdr->dst_port);
    if (payload) *payload = buf + header_size;
    if (payload_len) *payload_len = buf_len - header_size;
    return ERR_OK;
}
