# TCP proxy path (MSTCP revert) + relay adaptation

**Status**: done
**Serial**: T3
**Spec**: ../specs/2026-05-30-ndisapi-migration.md
**Depends on**: T2 (classification must be wired in so POLICY-classified packets reach the proxy path, and return-path classification works)

> The core feature. TCP traffic classified as POLICY is rewritten and injected via MSTCP revert to the local relay, which proxies it through SOCKS5. Return traffic from the relay is caught, rewritten back, and delivered to the client.

> **Done means**: TCP connections flow through the proxy via the MSTCP revert model. Relay listeners work with INADDR_ANY binding and actual-IP conntrack keys. WSL/Hyper-V TCP traffic intercepted.

## Goal

TCP traffic is transparently proxied through SOCKS5 using the MSTCP revert model. Relay listeners work with the new INADDR_ANY binding and conntrack key scheme.

## Acceptance

- [x] **Conntrack key change**: `path/proxy.c:add_proxy_conntrack()` — entry B key uses `(server_ip, relay_src_port, client_ip, relay_port)` with actual IPs
- [x] **Proxy path rewrite** (`path/proxy.c`):
  - For TCP SYN: swap IP.src↔IP.dst, set TCP.dport=relay_port, TCP.sport=relay_src_port
  - Swap Ethernet.src↔Ethernet.dst
  - Recalculate TCP and IP checksums
  - Redirect non-SYN tracked TCP: same rewrite
  - Untracked non-SYN TCP: drop (unchanged logic)
- [x] **MSTCP delivery**: after rewrite, `m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE`; packet sent via `SendPacketsToMstcpUnsorted`
- [x] **Relay listener** (`src/relay/tcp.c`):
  - `bind_tcp_listener`: `INADDR_ANY` (not INADDR_LOOPBACK)
  - `tcp_conn_start`: `getpeername()` returns peer IP; `getsockname()` gets local IP
  - Conntrack lookup uses actual IPs: `(peer_ip, peer_port, local_ip, relay_port, TCP)`
  - SOCKS5 handshake and relay logic unchanged
- [x] **Return path** (`path/return.c`):
  - Detection: `ON_SEND && src_port == relay_port` triggers TCP return
  - Lookup uses actual IPs matching entry B key scheme
  - Restore original tuple; MSS clamp unchanged
  - Delivery: `SendPacketsToMstcpUnsorted`
- [x] **Process lookup** (`src/process/lookup.c`): WinDivert flow event watcher removed; TCP/UDP owner-table polling only
- [x] **Executor** (`src/flow/executor.c`): `TRAFFIC_ACTION_REWRITE_SEND` uses ndisapi send calls based on direction flags
- [x] **Self/loop protection**: proxy IP:port bypass works; relay port self-protection works
- [x] All helper functions renamed from `divert_*` to `ndisapi_*` prefix

## Notes

- The MSTCP revert delivery replaces the old WinDivert loopback injection model.
- Conntrack entry B's keys use actual network IPs (not LOOPBACK_ADDR), matching the ndisapi packet flow.
- The TCP relay bind change (INADDR_ANY) allows accepting MSTCP-injected connections addressed to client IPs.
- `ndisapi_next_tcp_relay_src_port` uses same port-range cycling logic as before.
