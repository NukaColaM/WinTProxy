#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "core/common.h"
#include "app/log.h"
#include "app/config.h"
#include "conntrack/conntrack.h"
#include "process/lookup.h"
#include "policy/rules.h"
#include "dns/hijack.h"
#include "divert/adapter.h"
#include "relay/tcp.h"
#include "relay/udp.h"

static volatile int g_running = 1;

static conntrack_t      g_conntrack;
static proc_lookup_t    g_proc_lookup;
static dns_hijack_t     g_dns_hijack;
static divert_engine_t  g_divert;
static tcp_relay_t      g_tcp_relay;
static udp_relay_t      g_udp_relay;
static HANDLE           g_metrics_thread;

static DWORD WINAPI metrics_thread_proc(LPVOID param) {
    (void)param;
    while (g_running) {
        Sleep(30000);
        if (!g_running) break;
        divert_counters_t divert_counters;
        conntrack_counters_t conntrack_counters;
        proc_lookup_counters_t proc_counters;
        tcp_relay_counters_t tcp_counters;
        udp_relay_counters_t udp_counters;

        divert_snapshot_counters(&g_divert, &divert_counters);
        conntrack_snapshot_counters(&g_conntrack, &conntrack_counters);
        proc_lookup_snapshot_counters(&g_proc_lookup, &proc_counters);
        tcp_relay_snapshot_counters(&g_tcp_relay, &tcp_counters);
        udp_relay_snapshot_counters(&g_udp_relay, &udp_counters);

        LOG_INFO("perf: pkt recv=%llu sent=%llu drop=%llu send_fail=%llu udp_fwd=%llu; "
                 "ct add=%llu upd=%llu rem=%llu miss=%llu exhausted=%llu stale=%llu; "
                 "proc hit=%llu wildcard=%llu miss=%llu refresh=%llu flow_events=%llu; "
                 "tcp active=%llu accepted=%llu rejected=%llu up=%llu down=%llu; "
                 "udp active=%llu created=%llu evicted=%llu drop=%llu up=%llu down=%llu",
                 (unsigned long long)divert_counters.packets_recv,
                 (unsigned long long)divert_counters.packets_sent,
                 (unsigned long long)divert_counters.packets_dropped,
                 (unsigned long long)divert_counters.send_failures,
                 (unsigned long long)divert_counters.udp_forwarded,
                 (unsigned long long)conntrack_counters.adds,
                 (unsigned long long)conntrack_counters.updates,
                 (unsigned long long)conntrack_counters.removes,
                 (unsigned long long)conntrack_counters.misses,
                 (unsigned long long)conntrack_counters.pool_exhausted,
                 (unsigned long long)conntrack_counters.stale_cleanups,
                 (unsigned long long)proc_counters.flow_hits,
                 (unsigned long long)proc_counters.wildcard_hits,
                 (unsigned long long)proc_counters.misses,
                 (unsigned long long)proc_counters.refreshes,
                 (unsigned long long)proc_counters.flow_events,
                 (unsigned long long)tcp_counters.active_connections,
                 (unsigned long long)tcp_counters.accepted_connections,
                 (unsigned long long)tcp_counters.rejected_connections,
                 (unsigned long long)tcp_counters.bytes_up,
                 (unsigned long long)tcp_counters.bytes_down,
                 (unsigned long long)udp_counters.active_sessions,
                 (unsigned long long)udp_counters.created_sessions,
                 (unsigned long long)udp_counters.evicted_sessions,
                 (unsigned long long)udp_counters.dropped_datagrams,
                 (unsigned long long)udp_counters.bytes_up,
                 (unsigned long long)udp_counters.bytes_down);
    }
    return 0;
}

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
        "  --log <path>        Override logging.file from config\n"
        "  -v, --verbose       Override logging.level (repeat for more: -vv, -vvv, -vvvv)\n"
        "  --version           Show version\n"
        "  -h, --help          Show this help\n"
        "\n"
        "Examples:\n"
        "  %s --config config.json\n"
        "  %s --config config.json -vv\n"
        "\n"
        "NOTE: Must run as Administrator (WinDivert requires kernel access).\n"
        "      Download WinDivert.dll and WinDivert64.sys from\n"
        "      https://github.com/basil00/WinDivert/releases\n",
        prog, prog, prog);
}

int main(int argc, char *argv[]) {
    const char *config_path = NULL;
    const char *log_path = NULL;
    int verbosity = -1;
    int conntrack_ok = 0;
    int proc_lookup_ok = 0;
    int dns_ok = 0;
    int tcp_ok = 0;
    int udp_ok = 0;
    int divert_ok = 0;
    int exit_code = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            log_path = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            if (verbosity < LOG_INFO) verbosity = LOG_INFO;
            else if (verbosity < LOG_PACKET) verbosity++;
        } else if (strcmp(argv[i], "-vv") == 0) {
            verbosity = LOG_DEBUG;
        } else if (strcmp(argv[i], "-vvv") == 0) {
            verbosity = LOG_TRACE;
        } else if (strcmp(argv[i], "-vvvv") == 0) {
            verbosity = LOG_PACKET;
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

    if (config_apply_cli(&config, verbosity) != ERR_OK) {
        fprintf(stderr, "Invalid command-line logging override\n");
        config_free(&config);
        WSACleanup();
        return 1;
    }
    /* Initialize logging */
    const char *effective_log_path = log_path ? log_path : (config.logging.file[0] ? config.logging.file : NULL);
    log_init(config.logging.level, effective_log_path);

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

    if (proc_lookup_init(&g_proc_lookup) != ERR_OK) {
        LOG_ERROR("Failed to initialize process lookup");
        goto cleanup;
    }
    proc_lookup_ok = 1;

    if (dns_hijack_init(&g_dns_hijack, config.dns.enabled,
                        config.dns.redirect_ip_addr, config.dns.redirect_port) != ERR_OK) {
        LOG_ERROR("Failed to initialize DNS hijack state");
        goto cleanup;
    }
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

    if (divert_start(&g_divert, &config, &g_conntrack, &g_proc_lookup, &g_dns_hijack,
                     g_tcp_relay.port, g_udp_relay.port) != ERR_OK) {
        LOG_ERROR("Failed to start WinDivert engine");
        goto cleanup;
    }
    divert_ok = 1;

    g_metrics_thread = CreateThread(NULL, 0, metrics_thread_proc, NULL, 0, NULL);
    if (!g_metrics_thread) {
        LOG_WARN("Failed to start periodic metrics thread");
    }

    LOG_INFO("WinTProxy is running. Press Ctrl+C to stop.");

    while (g_running) {
        Sleep(500);
    }
    exit_code = 0;

cleanup:
    LOG_INFO("Shutting down...");

    if (g_metrics_thread) {
        g_running = 0;
        WaitForSingleObject(g_metrics_thread, 1000);
        CloseHandle(g_metrics_thread);
        g_metrics_thread = NULL;
    }

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
    return exit_code;
}
