#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "common.h"
#include "log.h"
#include "config.h"
#include "connection.h"
#include "process.h"
#include "rules.h"
#include "dns.h"
#include "divert.h"
#include "tcp_relay.h"
#include "udp_relay.h"

static volatile int g_running = 1;

static conntrack_t      g_conntrack;
static proc_lookup_t    g_proc_lookup;
static dns_hijack_t     g_dns_hijack;
static divert_engine_t  g_divert;
static tcp_relay_t      g_tcp_relay;
static udp_relay_t      g_udp_relay;

static BOOL WINAPI console_handler(DWORD ctrl) {
    if (ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT || ctrl == CTRL_CLOSE_EVENT) {
        LOG_INFO("Shutdown signal received...");
        g_running = 0;
        return TRUE;
    }
    return FALSE;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "WinTProxy " WINTPROXY_VERSION " - Transparent SOCKS5 Proxy for Windows\n"
        "\n"
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  --config <path>     Path to JSON config file\n"
        "  --proxy <addr:port> SOCKS5 proxy address (default: 127.0.0.1:7890)\n"
        "  --dns <addr:port>   Enable DNS hijacking (redirect to addr:port)\n"
        "  --log <path>        Write logs to file (in addition to stderr)\n"
        "  -v, --verbose       Increase verbosity (repeat for more: -vv, -vvv)\n"
        "  --version           Show version\n"
        "  -h, --help          Show this help\n"
        "\n"
        "Examples:\n"
        "  %s --proxy 127.0.0.1:7890\n"
        "  %s --config config.json --dns 127.0.0.1:1053 -vv\n"
        "\n"
        "NOTE: Must run as Administrator (WinDivert requires kernel access).\n"
        "      Download WinDivert.dll and WinDivert64.sys from\n"
        "      https://github.com/basil00/WinDivert/releases\n",
        prog, prog, prog);
}

int main(int argc, char *argv[]) {
    const char *config_path = NULL;
    const char *proxy_str = NULL;
    const char *dns_str = NULL;
    const char *log_path = NULL;
    int verbosity = -1;
    int conntrack_ok = 0;
    int proc_lookup_ok = 0;
    int dns_ok = 0;
    int tcp_ok = 0;
    int udp_ok = 0;
    int divert_ok = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--proxy") == 0 && i + 1 < argc) {
            proxy_str = argv[++i];
        } else if (strcmp(argv[i], "--dns") == 0 && i + 1 < argc) {
            dns_str = argv[++i];
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            log_path = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            if (verbosity < LOG_INFO) verbosity = LOG_INFO;
            else if (verbosity < LOG_TRACE) verbosity++;
        } else if (strcmp(argv[i], "-vv") == 0) {
            verbosity = LOG_DEBUG;
        } else if (strcmp(argv[i], "-vvv") == 0) {
            verbosity = LOG_TRACE;
        } else if (strcmp(argv[i], "--version") == 0) {
            fprintf(stderr, "WinTProxy " WINTPROXY_VERSION "\n");
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Initialize Winsock */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    /* Load config */
    app_config_t config;
    config_set_defaults(&config);

    if (config_path) {
        if (config_load(&config, config_path) != ERR_OK) {
            fprintf(stderr, "Failed to load config from: %s\n", config_path);
            WSACleanup();
            return 1;
        }
    }

    if (config_apply_cli(&config, proxy_str, dns_str, verbosity) != ERR_OK) {
        fprintf(stderr, "Invalid command-line proxy or DNS endpoint\n");
        config_free(&config);
        WSACleanup();
        return 1;
    }
    /* Initialize logging */
    const char *effective_log_path = log_path ? log_path : (config.log_file[0] ? config.log_file : NULL);
    log_init(config.log_level, effective_log_path);

    LOG_INFO("WinTProxy " WINTPROXY_VERSION " starting...");
    config_dump(&config);

    /* Set console handler for Ctrl+C */
    SetConsoleCtrlHandler(console_handler, TRUE);

    /* Initialize subsystems in dependency order.
     * Each shutdown reverses its corresponding init. */
    if (conntrack_init(&g_conntrack) != ERR_OK) {
        LOG_ERROR("Failed to initialize connection tracking");
        goto cleanup;
    }
    conntrack_ok = 1;

    proc_lookup_init(&g_proc_lookup);
    proc_lookup_ok = 1;

    dns_hijack_init(&g_dns_hijack, config.dns.enabled,
                    config.dns.redirect_ip_addr, config.dns.redirect_port);
    dns_ok = 1;

    if (tcp_relay_start(&g_tcp_relay, &g_conntrack, &config.proxy) != ERR_OK) {
        LOG_ERROR("Failed to start TCP relay");
        goto cleanup;
    }
    tcp_ok = 1;

    if (udp_relay_start(&g_udp_relay, &g_conntrack, &config.proxy) != ERR_OK) {
        LOG_ERROR("Failed to start UDP relay");
        goto cleanup;
    }
    udp_ok = 1;

    if (divert_start(&g_divert, &config, &g_conntrack, &g_proc_lookup, &g_dns_hijack) != ERR_OK) {
        LOG_ERROR("Failed to start WinDivert engine");
        goto cleanup;
    }
    divert_ok = 1;

    LOG_INFO("WinTProxy is running. Press Ctrl+C to stop.");

    while (g_running) {
        Sleep(500);
    }

cleanup:
    LOG_INFO("Shutting down...");

    if (divert_ok)  divert_stop(&g_divert);
    if (udp_ok)     udp_relay_stop(&g_udp_relay);
    if (tcp_ok)     tcp_relay_stop(&g_tcp_relay);
    if (dns_ok)     dns_hijack_shutdown(&g_dns_hijack);
    if (proc_lookup_ok) proc_lookup_shutdown(&g_proc_lookup);
    if (conntrack_ok)   conntrack_shutdown(&g_conntrack);
    config_free(&config);
    WSACleanup();

    LOG_INFO("WinTProxy stopped.");
    log_shutdown();
    return 0;
}
