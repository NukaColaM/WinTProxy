# WinTProxy Guide

## Build

Install the MinGW cross-compiler and configure CMake with the supplied toolchain:

```bash
sudo apt install gcc-mingw-w64-x86-64
cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-toolchain.cmake
cmake --build build
```

For a release build:

```bash
cmake -B build-release -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-toolchain.cmake
cmake --build build-release
```

## Runtime Requirements

- Windows 10 or later, 64-bit.
- Administrator privileges.
- [WinDivert](https://github.com/basil00/WinDivert/releases) 2.x runtime files next to `WinTProxy.exe`:
  - `WinDivert.dll`
  - `WinDivert64.sys`
- A SOCKS5 proxy reachable by IPv4 address.

## Running

```powershell
WinTProxy.exe --config config.example.json
WinTProxy.exe --config config.example.json -vv
WinTProxy.exe --config config.example.json --log wintproxy.log
```

Command-line options:

```text
  --config <path>     Path to JSON config file
  --log <path>        Override logging.file from config
  -v, --verbose       Override logging.level (-v=info, -vv=debug, -vvv=trace; -vvvv also clamps to trace)
  --version           Show version
  -h, --help          Show help
```

Traffic behavior is configured only in JSON. The former traffic override flags (`--proxy`, `--dns`) were removed so the runtime has a single source of truth.

## Configuration Reference

WinTProxy reads a strict JSON config file. All addresses must be IPv4 literals — hostnames are not resolved.

```json
{
    "capture": { "queue_length": 16384, "queue_time_ms": 100, "queue_size": 33554432 },
    "dns": { "enabled": true, "redirect_address": "127.0.0.1", "redirect_port": 1053 },
    "bypass": { "private_ips": false, "multicast": true, "broadcast": true },
    "policy": {
        "default_decision": "proxy",
        "rules": [
            { "process": "sockd.exe", "decision": "direct" },
            { "process": "chrome.exe,firefox.exe", "decision": "proxy" }
        ]
    },
    "proxy": { "address": "127.0.0.1", "port": 7890 },
    "logging": { "level": "info", "file": "" }
}
```

### Top-Level Sections

| Section | Description |
|---|---|
| `capture` | WinDivert adapter queue settings. Capture is intentionally broad enough for bypass/direct decisions to be visible in the planner instead of hidden in the filter. |
| `dns` | First-class DNS stage. When enabled, UDP/TCP port 53 traffic is handled before bypass and policy. |
| `bypass` | Non-proxyable/direct destination classes for non-DNS traffic: private/link-local/CGNAT, multicast, and broadcast. |
| `policy` | Ordered first-match proxy/direct rules and default decision. |
| `proxy` | SOCKS5 proxy endpoint. |
| `logging` | Async logger level and optional file path. |

### Policy Rules

Each policy rule can match by process, destination IP, destination port, and protocol. Omitted fields are wildcards.

```json
{
    "process": "chrome.exe,firefox.exe",
    "ip": "10.0.0.0/8;192.168.*.*",
    "port": "80,443,8080-8090",
    "protocol": "tcp",
    "decision": "proxy",
    "enabled": true
}
```

| Field | Description |
|---|---|
| `process` | Process names or wildcard patterns, comma/semicolon separated. `*` for all processes. |
| `ip` | Exact IPv4, CIDR, inclusive range (`1.2.3.0-1.2.3.255`), wildcard octets, or comma/semicolon separated list. |
| `port` | Exact port, inclusive range (`8080-8090`), or comma/semicolon separated list. |
| `protocol` | `tcp`, `udp`, or `both`. |
| `decision` | `proxy` or `direct`. `block` is intentionally removed. |
| `enabled` | Optional boolean (default true). |

Because matching is first-match-wins, place `direct` exceptions before broad `proxy` rules.

### Log Levels

| Level | Output |
|---|---|
| `error` | Startup/config failures and unrecoverable subsystem errors |
| `warn` | Recoverable degraded behavior, drops from missing state, fallback paths worth operator attention |
| `info` | Lifecycle, config summary, listener startup/shutdown (default); no recurring metrics noise |
| `debug` | Normal troubleshooting: proxy/direct/self-loop decisions, DNS query summaries, and readable periodic performance snapshots |
| `trace` | Relay/session lifecycle, packet rewrites, DNS TXID/NAT mapping internals, SOCKS5 handshake bytes, FLOW watcher internals, and other highest-volume diagnostics |

`-v` selects `info`, `-vv` selects `debug`, and `-vvv` selects `trace`; additional verbosity such as `-vvvv` is accepted but clamps to `trace`. Legacy `packet` is no longer a public level.

### Intentional Behavior and Interface Changes

- Policy-level `block` is removed. Packets are either proxied or sent direct, except internal safety drops for malformed/unsafe flows.
- CLI traffic overrides are removed; use config sections for proxy, DNS, bypass, and policy behavior.
- DNS hijacking is explicitly before bypass/policy. DNS traffic can be redirected even when its original destination is private or loopback.
- Private, multicast, and broadcast handling is modeled as explicit non-proxyable/direct path planning instead of a hidden filter-only behavior.

### Constraints

- SOCKS5 authentication is not supported.
- All proxied traffic uses a single SOCKS5 server.
- IPv4 only — IPv6 traffic passes through uninspected.

## Architecture

The codebase is organized by traffic-flow responsibility:

```text
src/app/          config, logging, process bootstrap, metrics
src/core/         common constants and utility helpers
src/divert/       WinDivert adapter: filter, queue, workers, send/receive I/O
src/packet/       packet parsing/cache/checksum/MSS helpers
src/flow/         verdict/action model, planner orchestration, executor
src/dns/          DNS NAT, DNS forwarding, UDP/TCP DNS planning
src/policy/       compiled ordered proxy/direct rule matching
src/path/         bypass, proxy path setup, and return-path restoration planning
src/conntrack/    connection tracking tables and lifecycle
src/process/      packet-to-process ownership lookup
src/relay/        SOCKS5 protocol helpers plus TCP/UDP relays
```

### Packet Flow

```text
WinDivert adapter (divert/adapter.c)
  → packet context parse (packet/context.c)
  → classify path (path/classify.c)
      ├─ inbound / DNS response / relay return / TCP-DNS return
      ├─ self/loop protection
      ├─ DNS query stage (before bypass and policy)
      ├─ non-DNS bypass/non-proxyable stage
      └─ policy stage
  → planner writes traffic_action_t
  → flow executor performs pass, drop, rewrite/send, DNS forward, or UDP relay forward
```

The planner/executor split is pragmatic: planners may perform required lookups or reservations (process lookup, conntrack, DNS NAT, relay source-port allocation), but final packet outcomes go through explicit actions.

### TCP

TCP SYN packets selected for proxying reserve conntrack state, are rewritten to a local relay port through WinDivert loopback injection, and produce a rewrite/send action. The relay opens a SOCKS5 connection, sends a CONNECT request for the original destination, and relays bytes bidirectionally.

Return traffic on loopback is classified as a return path, restored to the original tuple from conntrack, and injected as inbound traffic on the original adapter. TCP MSS is clamped to 1360 to avoid fragmentation after NAT rewrite.

Tracked non-SYN TCP packets are redirected to the relay using the existing conntrack mapping. Untracked TCP packets that policy would proxy are dropped because forwarding them direct would leak a proxied flow without a return mapping.

### UDP

UDP payloads selected for proxying reserve conntrack state and produce a `FORWARD_UDP_TO_RELAY` action. The executor forwards the payload to the local UDP relay with a source IP/port frame. The relay opens a SOCKS5 UDP ASSOCIATE control channel, wraps payloads in SOCKS5 UDP datagrams, and sends responses back through loopback for return-path restoration.

### DNS

When enabled, outbound DNS queries to port 53 are intercepted before bypass/policy.

- UDP DNS to a non-loopback resolver is rewritten to the configured resolver and restored on inbound response using DNS NAT.
- UDP DNS to a loopback resolver uses a socket forwarder with TXID remapping, then injects restored responses through WinDivert.
- TCP DNS is redirected with conntrack so the TCP return path can be restored like other stateful traffic.

Self/loop protection still prevents packets destined for the SOCKS5 proxy, local relay ports, and configured DNS resolver from being proxied into loops.

### Hot-Path State

All hot-path state uses fixed-size pools allocated at startup — no runtime allocation in the packet planner/executor path:

| Subsystem | Mechanism | Default Size |
|---|---|---|
| Policy | Compiled once at config load — patterns normalized, IP/port ranges sorted | — |
| Process lookup | Seeded by WinDivert flow events, repaired by background TCP/UDP owner-table index | 65536 flows, 8192 PIDs |
| Connection tracking | Hash table with per-bucket SRW locks, background TTL cleanup | 65536 entries, 16384 buckets |
| DNS NAT | Hash table keyed by client port + TXID, TTL 30s | 4096 entries, 256 buckets |
| TCP relay | Fixed worker pool, bounded active connection table | 32 workers, 8192 connections |
| UDP relay | Hashed client-port lookup, throttled SOCKS5 liveness checks | 256 sessions, 512 buckets |

Relay listeners prefer ports `34010` (TCP) and `34011` (UDP), with fallback to OS-assigned loopback ports.

### Subsystem Lifecycle

Initialization order (reverse on shutdown):

```text
Winsock → Config → Conntrack → Process lookup → DNS hijack → TCP relay → UDP relay → Divert adapter
```

A metrics thread logs grouped capture/conntrack/process/TCP/UDP performance snapshots at `debug` level. Counters are cumulative snapshots, emitted periodically for health checks rather than per-interval deltas. The default `info` level stays limited to lifecycle, config, and listener messages.
