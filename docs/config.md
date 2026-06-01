# Configuration

WinTProxy reads a strict JSON config file. All addresses must be IPv4 literals; hostnames are not resolved.

```json
{
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

## Sections

- `dns`: first-class DNS stage before bypass/policy.
- `bypass`: non-proxyable/direct destinations.
- `policy`: ordered first-match proxy/direct rules and default decision.
- `proxy`: SOCKS5 proxy endpoint.
- `logging`: async logger level and optional file path.

## Policy Rules

Rules match by process, destination IP, destination port, and protocol.
Use `proxy` or `direct` only. `block` is removed from the traffic model.

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
| `ip` | Exact IPv4, CIDR, inclusive range, wildcard octets, or comma/semicolon separated list. |
| `port` | Exact port, inclusive range, or comma/semicolon separated list. |
| `protocol` | `tcp`, `udp`, or `both`. |
| `decision` | `proxy` or `direct`. |
| `enabled` | Optional boolean, default true. |

Matching is first-match-wins, so direct exceptions should appear before broad proxy rules.

## Log Levels

- `error`: startup/config failures and unrecoverable subsystem errors
- `warn`: recoverable degraded behavior and attention-worthy drops
- `info`: lifecycle, config summary, listener startup/shutdown
- `debug`: routing decisions, DNS summaries, periodic performance snapshots
- `trace`: packet/protocol internals and highest-volume diagnostics

See `config.example.json` for a fully annotated example.

## Intentional Behavior

- DNS hijacking runs before bypass and policy.
- Private, multicast, and broadcast handling is an explicit bypass stage for non-DNS traffic.
- Policy-level `block` is removed. Unsafe or malformed flows may still be dropped internally.
- IPv6 traffic is out of scope.
