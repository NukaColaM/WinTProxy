# Configuration

WinTProxy reads a strict JSON config file. Command-line values override file values.

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

## Top-Level Fields

- `proxy.address`: SOCKS5 proxy IPv4 address.
- `proxy.port`: SOCKS5 proxy port in `1..65535`.
- `dns.enabled`: enable DNS hijacking.
- `dns.redirect_address`: DNS resolver IPv4 address.
- `dns.redirect_port`: DNS resolver port in `1..65535`.
- `rules`: ordered rule list. First match wins.
- `default_action`: `proxy`, `direct`, or `block`.
- `bypass_private_ips`: bypass RFC 1918, link-local, and CGNAT destinations before rule evaluation.
- `log_level`: `error`, `warn`, `info`, `debug`, `trace`, or `packet`.
- `log_file`: optional log file path.

## Rules

Each rule can match by process, destination IP, destination port, and protocol. Omitted match fields are treated as wildcards.

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

Rule fields:

- `process`: process names or wildcard patterns separated by commas or semicolons. Use `*` for all processes.
- `ip`: exact IPv4, CIDR, inclusive range, wildcard octets, or a comma/semicolon separated list.
- `port`: exact port, inclusive range, or a comma/semicolon separated list.
- `protocol`: `tcp`, `udp`, or `both`.
- `action`: `proxy`, `direct`, or `block`.
- `enabled`: optional boolean.

Because first match wins, place direct and block exceptions before broad proxy rules.

## Log Levels

- `info`: lifecycle and listener startup/shutdown.
- `debug`: process ownership, rule matches, and final decisions.
- `trace`: relay and session lifecycle.
- `packet`: packet rewrites, DNS transaction mapping, SOCKS5 handshake details, and other high-volume internals.
