# Classification + bypass + direction model

**Status**: done
**Serial**: T2
**Spec**: ../specs/2026-05-30-ndisapi-migration.md
**Depends on**: T1 (ndisapi engine, packet parsing, pass-through loop must exist before classification can be wired in)

> Builds on the pass-through loop from T1. Classification decides what to do with each packet. Bypass/self/non-proxyable paths pass through; proxy/dns paths wired in subsequent tasks.

> **Done means**: Classification runs on every packet. Debug logs show classification decisions with source/destination IPs and ports. Bypass, self-protection, and non-proxyable checks work. Policy and DNS traffic is classified and processed.

## Goal

Every captured packet is classified into a traffic class. Classification decisions are visible in trace/debug logs. Non-proxyable traffic correctly passes through or is blocked.

## Acceptance

- [x] `path/classify.c` updated: direction check uses `m_dwDeviceFlags & PACKET_FLAG_ON_SEND/RECEIVE` instead of `addr->Outbound`/`addr->Loopback`
- [x] Self/loop protection checks updated for ndisapi direction model:
  - `TRAFFIC_CLASS_TCP_RETURN`: detected by `ON_SEND && src_port == tcp_relay_port`
  - `TRAFFIC_CLASS_UDP_RETURN`: detected by `ON_SEND && src_port == udp_relay_port`
  - `TRAFFIC_CLASS_SELF_PROXY`: detected by `ON_SEND && dst_ip == proxy_ip && dst_port == proxy_port`
  - `TRAFFIC_CLASS_SELF_RELAY`: dst_port check unchanged
  - `TRAFFIC_CLASS_SELF_DNS`: dst_ip/dst_port check unchanged (plus outbound loopback resolver response)
  - Inbound classification: `!(m_dwDeviceFlags & PACKET_FLAG_ON_SEND)` instead of `!addr->Outbound`
- [x] DNS response classification updated:
  - Non-loopback DNS response: `ON_RECEIVE && src_ip == redirect_ip && src_port == redirect_port`
  - Loopback DNS response: handled via socket forwarder (T5); outbound DNS from redirect_ip detected as SELF_DNS
  - TCP DNS return: detected by `!ON_SEND && src_ip == redirect_ip && src_port == redirect_port && tcp` (ON_RECEIVE from DNS server)
- [x] `TRAFFIC_CLASS_NON_PROXYABLE` checks: broadcast (`0xFFFFFFFF`), multicast (`224-239.x.x.x`), private IPs — unchanged logic
- [x] `TRAFFIC_CLASS_POLICY` returns for all remaining outbound TCP/UDP
- [x] `flow/plan.c` dispatcher updated: all case labels use new traffic class values; includes updated from `divert/` to `ndisapi/`
- [x] `path/bypass.c` signature updated (removes `WINDIVERT_ADDRESS*`; direction comes from packet context); loopback self-traffic redirected to MSTCP
- [x] Debug/trace logs show classification decisions with class name, src_ip, src_port, dst_ip, dst_port, protocol
- [x] Traffic flows: bypass/direct/self traffic passes through; policy traffic proxied; DNS hijacked
- [x] Counters increment correctly: packets recv, sent, dropped

## Notes

- Classification logging is at TRACE level (not DEBUG as originally specified; consolidated during implementation).
- `TRAFFIC_CLASS_POLICY` packets are now fully proxied (wired in T3–T5, not stubbed).
- DNS query classification is fully wired (T4/T5).
- Return-path classes are fully operational.
- `TRAFFIC_CLASS_INBOUND` covers all non-DNS inbound traffic — passes through unchanged.
- DNS response loopback detection (`TRAFFIC_CLASS_DNS_RESPONSE_LOOPBACK`) is removed — loopback DNS handled via socket forwarder (T5).
