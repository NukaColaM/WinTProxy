# DNS hijack — loopback UDP + TCP DNS (both resolver types)

**Status**: done
**Serial**: T5
**Spec**: ../specs/2026-05-30-ndisapi-migration.md
**Depends on**: T4 (UDP DNS non-loopback and UDP proxy path — loopback UDP DNS and TCP DNS build on the same DNS plan/forwarder infrastructure)

> Completes DNS hijack for the remaining three modes: UDP loopback resolver (socket forwarder + Ethernet header construction), TCP DNS to non-loopback resolver, and TCP DNS to loopback resolver (source IP swap trick).

> **Done means**: All four DNS hijack modes work. DNS queries regardless of protocol (UDP/TCP) or resolver location (loopback/external) are redirected to the configured resolver.

## Goal

DNS hijack works in all four modes: UDP/non-loopback (from T4), UDP/loopback, TCP/non-loopback, TCP/loopback.

## Acceptance

- [x] **UDP loopback DNS** (`dns/hijack.c` forwarder thread):
  - Forwarder builds full Ethernet+IP+UDP+DNS packet with proper MACs from adapter table
  - Packet sent via `SendPacketsToMstcpUnsorted` (not WinDivert)
  - Stores `ndisapi_engine_t*` pointer instead of `divert_handle`
  - Adapter MAC address used for correct MSTCP delivery
- [x] **UDP loopback DNS query** (`dns/plan.c`):
  - `dns_plan_udp_query`: socket-forward path for `use_socket_fwd` mode
  - `traffic_action_forward_dns` handler passes DNS payload via `dns_hijack_forward_query`
- [x] **TCP DNS non-loopback** (`dns/plan.c`):
  - Outbound: `dns_plan_tcp_query` creates conntrack, rewrites dst to redirect resolver, sends to adapter
  - Response: `dns_plan_tcp_return` looks up conntrack, restores original tuple, sends to MSTCP
- [x] **TCP DNS loopback** (`dns/plan.c`):
  - Outbound: rewrites src to dns_server_ip, dst to 127.0.0.1:redirect_port, swaps Ethernet, sends to MSTCP
  - Resolver response routes to dns_server_ip → adapter → NDIS catches ON_SEND
  - Return path restores via conntrack lookup → MSTCP → client
- [x] All four DNS hijack modes implemented
- [x] DNS query trace logs show correct redirection paths

## Notes

- TCP DNS loopback uses source-IP-rewrite trick: forcing resolver responses to route through the external adapter for NDIS interception.
- The DNS forwarder thread uses heap-allocated INTERMEDIATE_BUFFER for MSTCP injection (driver handle uses FILE_FLAG_OVERLAPPED).
- `dns_plan_udp_response_loopback` (`TRAFFIC_CLASS_DNS_RESPONSE_LOOPBACK`) is removed — loopback DNS responses handled entirely within the forwarder thread.
- All four modes share the same DNS NAT infrastructure (TXID remapping, 30s TTL).
