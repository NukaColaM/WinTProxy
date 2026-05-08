# Project Map
_Generated: 2026-05-08 16:10 | Git: 9382e69_

## Directory Structure
`src/` — 11 C source files: main, config, connection, process, rules, socks5, dns, divert, tcp_relay, udp_relay, log
`inc/` — 14 headers, one per module plus common.h and constants.h
`lib/` — vendored cJSON + WinDivert import library and headers
`cmake/` — MinGW cross-compilation toolchain file

## Key Files
- `src/main.c` — entry point: CLI parsing, subsystem init/teardown in dependency order, 30s metrics thread, Ctrl+C shutdown
- `src/divert.c` — core packet engine: 4 WinDivert worker threads, packet classification, NAT rewrite, loopback injection, rule evaluation dispatch (942 lines — largest file)
- `src/tcp_relay.c` — TCP proxy relay: worker pool, SOCKS5 CONNECT, bidirectional byte forwarding, MSS clamping, connection table
- `src/udp_relay.c` — UDP proxy relay: SOCKS5 UDP ASSOCIATE, session tracking, throttled liveness checks
- `src/dns.c` — DNS hijacking: UDP query interception, NAT by client port+TXID, loopback forwarding socket
- `src/connection.c` — connection tracking (conntrack): fixed-pool hash table with SRW locks, TTL cleanup thread
- `src/process.c` — process ownership lookup: WinDivert flow events + TCP/UDP owner-table background repair
- `src/rules.c` — rule matching: first-match-wins, pattern compilation (wildcard/exact/prefix/suffix/contains)
- `src/config.c` — strict JSON config loading via cJSON, CLI override merging, validation
- `inc/constants.h` — all tunable constants: table sizes, TTLs, port numbers, buffer sizes, worker counts
- `inc/common.h` — shared types: error_t enum, pkt_type_t classification enum, version string
- `CMakeLists.txt` — cross-compile with MinGW, links ws2_32/iphlpapi/psapi + WinDivert .a import lib
- `guide.md` — consolidated reference: build, configuration, architecture, hot-path state overview
- `config.example.json` — annotated example covering all configuration options with inline explanations

## Critical Constraints
- All config addresses must be IPv4 literals — no hostname resolution
- SOCKS5 authentication is not supported
- Rule matching is first-match-wins, not most-specific — place deny/allow exceptions before broad rules
- WinDivert cannot reliably inject into loopback; DNS to loopback resolvers uses a UDP forwarding socket instead
- Relay listeners prefer ports 34010/34011 with fallback to OS-assigned loopback ports
- TCP MSS is clamped to 1360 to avoid fragmentation after NAT rewrite
- Vendor `lib/cJSON/cJSON.c` — do not replace with system cJSON (MinGW cross-compile target)
- Requires Administrator privileges and WinDivert.dll + WinDivert64.sys at runtime

## Hot Files
`src/divert.c`, `src/tcp_relay.c`, `src/udp_relay.c`, `src/dns.c`, `src/connection.c`, `src/main.c`, `inc/constants.h`
