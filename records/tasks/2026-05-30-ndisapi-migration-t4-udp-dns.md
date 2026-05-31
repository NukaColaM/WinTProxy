# UDP proxy path + non-loopback DNS hijack

**Status**: complete
**Serial**: T4
**Spec**: ../specs/2026-05-30-ndisapi-migration.md
**Depends on**: T3 (TCP proxy + relay changes must exist — UDP shares conntrack, relay infrastructure, and the ndisapi executor)

> UDP traffic classified as POLICY is forwarded to the relay for SOCKS5 UDP ASSOCIATE proxying. UDP DNS queries to non-loopback resolvers are hijacked (rewritten to configured resolver). Return paths for both are handled.

> **Done means**: UDP applications work through the proxy. DNS queries to external resolvers are redirected and responses restored correctly.

## Goal

UDP traffic is proxied via SOCKS5 UDP ASSOCIATE. UDP DNS hijack to non-loopback resolvers works end-to-end.

## Acceptance

- [x] **UDP relay** (`src/relay/udp.c`):
  - `bind_udp_listener`: `INADDR_ANY` (not INADDR_LOOPBACK)
  - Response `sendto()` destination: `orig_dst_ip:client_port` (looked up from conntrack)
- [x] **UDP proxy conntrack** (`path/proxy.c`):
  - Entry A unchanged
  - Entry B key uses `(server_ip, client_port, ...)` — actual IPs, not LOOPBACK_ADDR
- [x] **UDP forward to relay** (`flow/executor.c`):
  - `TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY`: frame payload, send via `sendto()` to loopback relay port
- [x] **UDP return path** (`path/return.c`):
  - Return detected by `ON_SEND && src_port == udp_relay_port`
  - Lookup: `conntrack_get_full` with `(ctx->dst_ip, ctx->dst_port, proto)`
  - Restore original tuple; deliver via `SendPacketsToMstcpUnsorted`
- [x] **UDP DNS non-loopback hijack** (`dns/plan.c`):
  - Outbound query: rewrite dst to redirect resolver, send to adapter
  - Inbound response: restore src to original DNS IP/port, send to MSTCP
- [x] **DNS response classification**: non-loopback response detected by `ON_RECEIVE && src_ip==redirect_ip && src_port==redirect_port`
- [x] UDP DNS queries to configured resolver work (external resolver case)

## Notes

- UDP relay uses conntrack to retrieve `orig_dst_ip` for response routing, forcing responses through the external adapter for NDIS interception.
- UDP DNS responses from non-loopback resolvers arrive as ON_RECEIVE packets, get NAT-restored, then delivered via MSTCP.
- Loopback DNS (UDP and TCP) is handled in T5.
- The `traffic_dns_forward_t` struct includes `adapter_handle` for MSTCP response delivery.
