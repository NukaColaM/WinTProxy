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
WinTProxy.exe --config examples\basic.json
WinTProxy.exe --proxy 127.0.0.1:7890 --dns 127.0.0.1:1053 -vv
```

Command-line options:

```text
  --config <path>     Path to JSON config file
  --proxy <addr:port> SOCKS5 proxy address (default: 127.0.0.1:7890)
  --dns <addr:port>   Enable DNS hijacking (redirect to addr:port)
  --log <path>        Write logs to file (in addition to stderr)
  -v, --verbose       Increase verbosity (repeat: -vv, -vvv, -vvvv)
  --version           Show version
  -h, --help          Show help
```

CLI options override config file values.

## Configuration Reference

WinTProxy reads a strict JSON config file. All addresses must be IPv4 literals — hostnames are not resolved.

```json
{
    "proxy": { "address": "127.0.0.1", "port": 7890 },
    "dns": { "enabled": false, "redirect_address": "127.0.0.1", "redirect_port": 1053 },
    "rules": [],
    "default_action": "proxy",
    "bypass_private_ips": false,
    "log_level": "info",
    "log_file": ""
}
```

### Top-Level Fields

| Field | Type | Description |
|---|---|---|
| `proxy.address` | string | SOCKS5 proxy IPv4 address |
| `proxy.port` | int | SOCKS5 proxy port (1–65535) |
| `dns.enabled` | bool | Enable DNS hijacking |
| `dns.redirect_address` | string | DNS resolver IPv4 address |
| `dns.redirect_port` | int | DNS resolver port (1–65535) |
| `rules` | array | Ordered rule list — first match wins |
| `default_action` | string | `proxy`, `direct`, or `block` |
| `bypass_private_ips` | bool | Bypass RFC 1918, link-local, and CGNAT destinations before rule evaluation |
| `log_level` | string | `error`, `warn`, `info`, `debug`, `trace`, or `packet` |
| `log_file` | string | Optional log file path |

### Rules

Each rule can match by process, destination IP, destination port, and protocol. Omitted fields are wildcards.

```json
{
    "process": "chrome.exe,firefox.exe",
    "ip": "10.0.0.0/8;192.168.*.*",
    "port": "80,443,8080-8090",
    "protocol": "tcp",
    "action": "proxy",
    "enabled": true
}
```

| Field | Description |
|---|---|
| `process` | Process names or wildcard patterns, comma/semicolon separated. `*` for all processes |
| `ip` | Exact IPv4, CIDR, inclusive range (`1.2.3.0-1.2.3.255`), wildcard octets, or comma/semicolon separated list |
| `port` | Exact port, inclusive range (`8080-8090`), or comma/semicolon separated list |
| `protocol` | `tcp`, `udp`, or `both` |
| `action` | `proxy`, `direct`, or `block` |
| `enabled` | Optional boolean (default true) |

Because matching is first-match-wins, place `direct` and `block` exceptions before broad `proxy` rules.

### Log Levels

| Level | Output |
|---|---|
| `error` | Fatal conditions only |
| `warn` | Recoverable problems |
| `info` | Lifecycle, listener startup/shutdown (default) |
| `debug` | Process ownership, rule matches, final decisions |
| `trace` | Relay and session lifecycle |
| `packet` | Packet rewrites, DNS TXID mapping, SOCKS5 handshake details |

### Constraints

- SOCKS5 authentication is not supported.
- All proxied traffic uses a single SOCKS5 server.
- IPv4 only — IPv6 traffic passes through uninspected.

## Architecture

WinDivert captures outbound packets before they leave the network stack. WinTProxy classifies each packet by process name, evaluates configured rules, and applies the selected action.

### Packet Flow

```
Outbound packet → WinDivert filter → Process lookup → Rule evaluation
                                          ↓                  ↓
                                    DNS hijack?        proxy/direct/block
                                          ↓
                                    Conntrack lookup → NAT rewrite → Relay or reinject
```

### TCP

TCP SYN packets selected for proxying are rewritten to a local relay port through WinDivert loopback injection. The relay opens a SOCKS5 connection, sends a CONNECT request for the original destination, and relays bytes bidirectionally.

Return traffic on loopback is intercepted, restored to the original tuple from connection tracking, and injected as inbound traffic on the original adapter. TCP MSS is clamped to 1360 to avoid fragmentation after NAT rewrite.

### UDP

UDP payloads selected for proxying are forwarded to the local UDP relay with a source-port header. The relay opens a SOCKS5 UDP ASSOCIATE control channel, wraps payloads in SOCKS5 UDP datagrams, and sends responses back through loopback for packet injection.

### DNS

When enabled, outbound DNS queries to port 53 are intercepted before rule evaluation and redirected to the configured resolver. Loopback resolvers use a UDP forwarding socket because WinDivert cannot reliably inject packets into the loopback stack. DNS NAT is keyed by client port and TXID.

### Hot-Path State

All hot-path state uses fixed-size pools allocated at startup — no runtime allocation:

| Subsystem | Mechanism | Default Size |
|---|---|---|
| Rules | Compiled once at config load — patterns normalized, IP/port ranges sorted | — |
| Process lookup | Seeded by WinDivert flow events, repaired by background TCP/UDP owner-table index | 65536 flows, 8192 PIDs |
| Connection tracking | Hash table with per-bucket SRW locks, background TTL cleanup | 65536 entries, 16384 buckets |
| DNS NAT | Hash table keyed by client port + TXID, TTL 30s | 4096 entries, 256 buckets |
| TCP relay | Fixed worker pool, bounded active connection table | 32 workers, 8192 connections |
| UDP relay | Hashed client-port lookup, throttled SOCKS5 liveness checks | 256 sessions, 512 buckets |

Relay listeners prefer ports `34010` (TCP) and `34011` (UDP), with fallback to OS-assigned loopback ports.

### Subsystem Lifecycle

Initialization order (reverse on shutdown):

```
Winsock → Config → Conntrack → Process lookup → DNS hijack → TCP relay → UDP relay → Divert engine
```

A 30-second metrics thread logs aggregate counters for each subsystem.
