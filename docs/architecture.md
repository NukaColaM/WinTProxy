# Architecture

WinDivert captures outbound packets before they leave the network stack. WinTProxy classifies each packet by process name, evaluates configured rules, and applies the selected action.

## TCP

TCP SYN packets selected for proxying are rewritten to a local relay port through WinDivert loopback injection. The relay opens a SOCKS5 connection, sends a CONNECT request for the original destination, and relays bytes bidirectionally.

Return traffic on loopback is intercepted, restored to the original source and destination tuple from connection tracking, and injected as inbound traffic on the original adapter.

## UDP

UDP payloads selected for proxying are forwarded to the local UDP relay with a source-port header. The relay opens a SOCKS5 UDP ASSOCIATE control channel, wraps payloads in SOCKS5 UDP datagrams, and sends responses back through loopback for packet injection.

## DNS

When enabled, outbound DNS queries to port 53 are intercepted before rule evaluation and redirected to the configured resolver. Loopback resolvers use a UDP forwarding socket because WinDivert cannot reliably inject packets into the loopback stack.

## Hot-Path State

- Rules are compiled when config loads. Process patterns are normalized once, and IP/port patterns are stored as sorted numeric ranges.
- Process ownership lookup is seeded by WinDivert flow events and repaired by a background TCP/UDP owner-table index.
- Conntrack and DNS NAT entries come from fixed pools.
- TCP relay connections use a fixed worker pool and bounded active connection table.
- UDP sessions use hashed client-port lookup and throttled SOCKS5 control-channel liveness checks.
- Relay listeners prefer ports `34010` and `34011`, with fallback to OS-assigned loopback ports.
