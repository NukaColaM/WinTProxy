# Proxifyre ndisapi Packet Flow Research

**Date**: 2026-05-30
**Prompted by**: Q3 (loopback/relay path decision)

## What was investigated

How Proxifyre (`github.com/wiresock/proxifyre`) uses ndisapi's WinpkFilter driver to intercept and redirect TCP/UDP traffic to local SOCKS5 proxy servers. Specifically the `queued_multi_interface_packet_filter`, `tcp_local_redirect`, `socks5_udp_local_redirect`, and `socks_local_router` components.

## Findings

### Packet interception architecture

Proxifyre uses ndisapi's `queued_multi_interface_packet_filter` with only an **outgoing** filter functor (incoming is `nullptr`). All traffic is handled from the outgoing send path.

### The `revert` action mechanism

ndisapi's pipeline supports a `revert` action that reverses the packet's direction:

```
Outgoing (ON_SEND) + revert → SendPacketsToMstcpUnsorted (up the TCP/IP stack)
Incoming (ON_RECEIVE) + revert → SendPacketsToAdaptersUnsorted (out to wire)
```

### Client → Proxy (outgoing redirect)

```
Client sends SYN to example.com:443
  ↓ NDIS captures (PACKET_FLAG_ON_SEND)
  ↓ tcp_local_redirect::process_client_to_server_packet():
      swap(Ethernet src, Ethernet dst)
      swap(IP src, IP dst)
      tcp.dport = proxy_port (network byte order)
      recalculate TCP and IP checksums
  ↓ action = revert
  ↓ revert + ON_SEND → SendPacketsToMstcpUnsorted()
  ↓ OS TCP/IP stack delivers to proxy socket on 127.0.0.1:proxy_port
```

### Proxy → Client (response rewrite)

```
Proxy socket sends response (proxy_port → client_ip:client_port)
  ↓ NDIS captures (PACKET_FLAG_ON_SEND — outgoing socket write)
  ↓ tcp_local_redirect::process_server_to_client_packet():
      swap(Ethernet src, Ethernet dst)
      swap(IP src, IP dst)
      tcp.sport = original_server_port (from connection map)
      recalculate TCP and IP checksums
  ↓ action = revert
  ↓ revert + ON_SEND → SendPacketsToMstcpUnsorted()
  ↓ OS TCP/IP stack delivers to client socket as if from original server
```

### Connection tracking

- **TCP**: `tcp_mapper_` maps client source port → (original destination IP, port, timestamp). Entries created on SYN, consumed on proxy accept, expired after 30s TTL.
- **UDP**: `udp_mapper_` tracks which source ports are being UDP-proxied. Entries created on first datagram, expired after 15min.

### Process resolution

- `iphelper::process_lookup` maps TCP/UDP connections to owning processes.
- When lookup fails inline (process table not yet populated), packet is **queued for deferred resolution** (`enqueue_for_deferred_resolve`), then dropped from current pass.
- A dedicated resolver thread drains the queue, refreshes the process table, and re-processes queued packets.
- Queue depth is bounded at 2048 entries; overflow packets are dropped with throttled logging.

### Adapter management

Proxifyre filters adapters with external connectivity only (`iphelper::network_adapter_info::get_external_network_connections()`), excluding PPP-type adapters. WAN adapters are matched by RAS link IP addresses.

### Static filters

Proxifyre uses ndisapi's static filter table for:
- ICMP pass-through (all ICMP traffic)
- LAN bypass (10.x, 172.16-31.x, 192.168.x, 224.x, 169.254.x subnets — pass-through in both directions)
- Proxy endpoint pass-through (packets to/from the SOCKS5 proxy's IP:port bypass the filter)

### Checksum handling

`CNdisApi::RecalculateTCPChecksum()` and `CNdisApi::RecalculateIPChecksum()` (available as C exports) are called after every header modification. No `WinDivertHelperCalcChecksums` equivalent needed.

## Implications

1. **WinTProxy's relay listeners (`tcp_relay_t`, `udp_relay_t`) remain fully unchanged.** They still bind loopback sockets, accept connections, do SOCKS5 handshakes, and relay bytes. Only the delivery mechanism changes from WinDivert loopback injection to MSTCP revert.

2. **Return-path detection changes.** Currently, WinTProxy detects relay return traffic on inbound loopback (`addr->Loopback && addr->Outbound && src_port==relay_port`). With ndisapi, relay return traffic is caught on outgoing adapter send path (`PACKET_FLAG_ON_SEND && src_port==relay_port`), since the relay's socket sends data outbound.

3. **The deferred process resolution pattern may be needed.** Proxifyre's `enqueue_for_deferred_resolve` handles the race where the process lookup table hasn't yet mapped a new connection. WinTProxy currently does process lookup inline; this may need similar treatment.

4. **Ethernet-level packet format.** ndisapi delivers full Ethernet frames, not IP-layer packets. WinTProxy's `packet_ctx_t` must add `ether_header_ptr` and parse from Ethernet → IP → TCP/UDP.

5. **Multi-adapter handles.** Each `INTERMEDIATE_BUFFER` carries an `m_hAdapter` (network interface handle) and `m_dwDeviceFlags` (ON_SEND/ON_RECEIVE). WinDivert's single global handle model must be replaced with per-packet adapter-aware I/O.
