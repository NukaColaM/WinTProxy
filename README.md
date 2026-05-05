# WinTProxy

Transparent SOCKS5 proxy for Windows. Intercepts TCP/UDP traffic at the packet level via [WinDivert](https://github.com/basil00/WinDivert).

## Features

- **Transparent rule-based proxying** — match traffic by process name and IP/port patterns, then proxy, block, or send direct. Rules are evaluated in order; first match wins.
- **DNS hijacking** — intercept outbound DNS queries (port 53) before rule evaluation and redirect to a local resolver

## How it works

WinDivert captures outbound packets before they leave the network stack. WinTProxy classifies each packet by process name, evaluates user-defined rules, and decides the action.

**TCP:** SYN packets are rewritten to a local relay port via WinDivert loopback injection. The relay performs a SOCKS5 CONNECT handshake to the upstream proxy, then relays data bidirectionally. Return traffic on loopback is intercepted, original destinations are restored from connection tracking, and the response is injected as an inbound packet on the original adapter.

**UDP:** Payloads are forwarded to a local relay with a source-port header. The relay performs a SOCKS5 UDP ASSOCIATE handshake, wraps/unwraps payloads in SOCKS5 UDP datagrams, and responses are sent back through loopback for injection.

**DNS hijacking:** outbound DNS queries (port 53) are intercepted before rule evaluation and redirected to the configured resolver. Loopback resolvers use a UDP forwarding socket because WinDivert cannot reliably inject packets into the loopback stack.

A connection-tracking table keyed on `(source_port, protocol)` stores original destination IP/port and adapter interface index for return-path restoration.

## Building

Cross-compile with MinGW from WSL2 or Linux:

```bash
sudo apt install gcc-mingw-w64-x86-64

# Generate WinDivert import library (one-time)
x86_64-w64-mingw32-dlltool -d lib/windivert/WinDivert.def -l lib/windivert/libWinDivert.a

# Build
cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-toolchain.cmake
cmake --build build
```

## Usage

```
WinTProxy.exe [options]

Options:
  --config <path>     Path to JSON config file
  --proxy <addr:port> SOCKS5 proxy address (default: 127.0.0.1:7890)
  --dns <addr:port>   Enable DNS hijacking (redirect to addr:port)
  --log <path>        Write logs to file (in addition to stderr)
  -v, --verbose       Increase verbosity (-v info, -vv debug, -vvv trace)
  --version           Show version
  -h, --help          Show help
```

```bash
# Proxy all traffic through local SOCKS5
WinTProxy.exe --proxy 127.0.0.1:7890

# With config file and DNS hijacking
WinTProxy.exe --config config.json --dns 127.0.0.1:1053 -vv
```

## Configuration

See [`config.example.json`](config.example.json) for a complete example. Command-line options override config file values.

```jsonc
{
    "proxy": { "address": "127.0.0.1", "port": 7890 },
    "dns": { "enabled": true, "redirect_address": "127.0.0.1", "redirect_port": 1053 },
    "rules": [ ... ],
    "default_action": "proxy",
    "log_level": "info",
    "log_file": ""
}
```

Configuration is intentionally strict:

- `address` and `redirect_address` must be IPv4 literals.
- `port`, `redirect_port`, and rule ports must be in `1..65535`.
- `default_action` and rule `action` must be `proxy`, `direct`, or `block`.
- Rule `protocol` must be `tcp`, `udp`, or `both`.
- Malformed JSON, wrong value types, invalid IP patterns, truncated strings, and short file reads fail startup.

### Rules

Rules are evaluated in order; first match wins. When no rule matches, `default_action` applies.

```jsonc
{
    "process": "chrome.exe",    // optional; wildcards, commas, "*" for all
    "ip": "10.0.0.0/8",        // optional; CIDR, range, wildcard octets, semicolon-separated
    "port": "80,443",           // optional; exact, range, comma-separated
    "protocol": "tcp",          // optional; "tcp", "udp", "both" (default)
    "action": "proxy"           // "proxy", "direct", "block"
}
```

All match fields are optional. A rule with no match fields matches everything. Because first match wins, put broad wildcard rules after more specific direct/block rules.

IP patterns support exact IPv4 addresses, CIDR (`10.0.0.0/8`), inclusive ranges (`10.0.0.1-10.0.0.20`), wildcard octets (`192.168.*.*`), and semicolon-separated lists. Port patterns support exact ports, inclusive ranges, comma lists, and semicolon lists.

`bypass_private_ips` bypasses RFC 1918, link-local, and CGNAT destinations before rule evaluation.

## Requirements

- Windows 10 or later (64-bit)
- Administrator privileges
- [WinDivert](https://github.com/basil00/WinDivert/releases) 2.x runtime files (`WinDivert.dll`, `WinDivert64.sys`) alongside the executable
- A running SOCKS5 proxy (e.g. [Dante](https://www.inet.no/dante/))

## Known limitations

- **IPv4 only** — IPv6 traffic is not intercepted
- **No SOCKS5 authentication** — only NO AUTH (0x00) is supported
- **Loopback interface index** default (`IfIdx=1`) may not be correct on all machines
- **Single proxy** — all proxied traffic routed through one SOCKS5 server
- **No domain-based SOCKS5** — only IPv4 addresses (ATYP 0x01) sent to the proxy
- **Strict IPv4 config** - hostnames are not resolved from `proxy.address`, `dns.redirect_address`, or IP rules

## License

Third-party components:
- [WinDivert](https://github.com/basil00/WinDivert) — LGPL-3.0
- [cJSON](https://github.com/DaveGamble/cJSON) — MIT
