# Architecture

## Flow

`ndisapi adapter -> packet parse -> classify -> plan -> execute`

The planner produces a `traffic_action_t`. The executor owns the final packet
mutation and send path.

```text
ndisapi adapter
  -> packet context parse
  -> classify path
      - inbound / DNS response / relay return / TCP-DNS return
      - self/loop protection
      - DNS query stage
      - non-DNS bypass/non-proxyable stage
      - policy stage
  -> planner writes traffic_action_t
  -> executor performs pass, drop, rewrite/send, DNS forward, or UDP relay forward
```

## Subsystems

- `src/app/`: config, logging, bootstrap, lifecycle, metrics
- `src/core/`: shared constants and helpers
- `src/ndisapi/`: driver, adapter enumeration, workers, batch I/O
- `src/packet/`: packet parsing and checksum helpers
- `src/flow/`: action model, planner orchestration, executor
- `src/dns/`: DNS NAT, forwarding, UDP/TCP DNS planning
- `src/policy/`: ordered proxy/direct rule matching
- `src/path/`: bypass, proxy, and return-path planning
- `src/conntrack/`: connection tracking tables and lifecycle
- `src/process/`: packet-to-process ownership lookup
- `src/relay/`: SOCKS5 helpers plus TCP/UDP relays

## TCP

TCP SYN packets selected for proxying reserve conntrack state, are rewritten to a local relay port, and are delivered to MSTCP. The relay opens a SOCKS5 CONNECT request for the original destination and relays bytes both ways.

Tracked non-SYN TCP packets are redirected with the existing conntrack mapping. Untracked TCP packets that policy would proxy are dropped closed because forwarding them direct would leak the flow without a return mapping.

## UDP

UDP packets selected for proxying reserve conntrack state and produce a `FORWARD_UDP_TO_RELAY` action. The relay uses SOCKS5 UDP ASSOCIATE and sends responses back through the adapter so return-path restoration remains centralized.

## DNS

DNS runs before bypass and policy:

- UDP DNS to a non-loopback resolver is rewritten and restored with DNS NAT.
- UDP DNS to a loopback resolver uses a socket forwarder with TXID remapping.
- TCP DNS is redirected with conntrack so the TCP return path is restored like other stateful traffic.

## Hot-Path State

| Subsystem | Mechanism | Default Size |
|---|---|---|
| Process lookup | Background TCP/UDP owner-table index | 65536 flows, 8192 PIDs |
| Connection tracking | Hash table with per-bucket locks and TTL cleanup | 65536 entries, 16384 buckets |
| DNS NAT | Hash table keyed by client port and TXID | 4096 entries, 256 buckets |
| TCP relay | Worker pool and bounded active connection table | 32 workers, 512 connections |
| UDP relay | Hashed client-port lookup | 256 sessions, 512 buckets |
