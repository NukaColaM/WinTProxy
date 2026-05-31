# Replace WinDivert with ndisapi (WinpkFilter)

**Status**: done

## Problem

WinTProxy uses WinDivert (a WFP-based packet interception library) as its core packet engine. WinDivert operates at the Windows Filtering Platform layer and cannot intercept traffic from WSL (Windows Subsystem for Linux) or Hyper-V virtual machines because those subsystems use virtual network adapters that bypass the WFP callout path. Users running WSL or Hyper-V cannot transparently proxy their traffic through WinTProxy.

## Solution

Replace the WinDivert packet interception layer with ndisapi (the WinpkFilter NDIS driver and user-mode DLL, `github.com/wiresock/ndisapi`). ndisapi operates at the NDIS (Ethernet) layer and can intercept all network traffic regardless of source — including WSL vEthernet and Hyper-V virtual switch adapters.

The replacement uses ndisapi's `extern "C"` C API, preserving WinTProxy's pure-C codebase. The MSTCP revert model (validated by the Proxifyre reference implementation) delivers proxied packets to local relay listeners through the OS TCP/IP stack, leaving the relay subsystem unchanged. All DNS hijack modes (UDP non-loopback, UDP loopback, TCP non-loopback, TCP loopback) are preserved.

## User stories

1. As a user, I want WSL and Hyper-V traffic to be proxied, so that all my system's network traffic is transparently routed through the SOCKS5 proxy. ← Q1, Q4

2. As a developer, I want the packet interception engine to use ndisapi.dll's C API, so that the project stays pure C and the build system remains Mingw-compatible. ← Q2

3. As a developer, I want proxied packets to reach local relay listeners via the OS TCP/IP stack (MSTCP revert), so that the existing TCP/UDP relay subsystems remain unchanged in logic. ← Q3, Q5

4. As a developer, I want the I/O model to use simple multi-worker batch processing, so that packet throughput is maximized without unnecessary pipeline queue complexity. ← Q6

5. As a developer, I want WinDivert-specific types replaced directly with ndisapi types throughout the codebase, so that there is a single source of truth and no mapping indirection for debugging. ← Q7

## Technical decisions

### Modules to build or modify

#### New files
- `inc/ndisapi/adapter.h` — ndisapi engine struct and function declarations (replaces `inc/divert/adapter.h`)
- `inc/ndisapi/io.h` — ndisapi I/O helpers (replaces `inc/divert/io.h`)
- `inc/net/headers.h` — Ethernet, IPv4, TCP, UDP header struct typedefs (replaces WinDivert header types; adapted from Proxifyre's `iphlp.h`)
- `src/ndisapi/adapter.c` — ndisapi engine: driver open/close, adapter enumeration, worker threads, batch I/O (replaces `src/divert/adapter.c`)
- `src/ndisapi/io.c` — ndisapi I/O helpers (replaces `src/divert/io.c` — actually the I/O helpers may be merged into adapter.c)
- `lib/ndisapi/ndisapi.h` — vendored copy of ndisapi.dll's C API header (from `github.com/wiresock/ndisapi/include/ndisapi.h`)
- `lib/ndisapi/Common.h` — vendored copy of WinpkFilter common definitions

#### Modified files
- `inc/packet/context.h` — replace `PWINDIVERT_IPHDR`/`PWINDIVERT_TCPHDR`/`PWINDIVERT_UDPHDR` with `iphdr_ptr`/`tcphdr_ptr`/`udphdr_ptr`; add `ether_header_ptr`; remove `WINDIVERT_ADDRESS` dependency
- `src/packet/context.c` — replace `WinDivertHelperParsePacket` with manual Ethernet→IP→TCP/UDP parsing; replace `WinDivertHelperCalcChecksums` with `RecalculateIPChecksum`/`RecalculateTCPChecksum`/`RecalculateUDPChecksum`
- `inc/flow/action.h` — replace `WINDIVERT_ADDRESS*` with ndisapi direction metadata; update traffic action struct
- `src/flow/action.c` — update action init signatures
- `src/flow/executor.c` — replace `divert_send_packet` with ndisapi send calls; update UDP and DNS forward actions
- `src/flow/plan.c` — update include from `divert/` to `ndisapi/`
- `inc/path/classify.h` — update traffic class declarations if needed
- `src/path/classify.c` — replace `addr->Outbound/Loopback` with `m_dwDeviceFlags & PACKET_FLAG_ON_SEND/RECEIVE`; update self/loop detection; update DNS response detection
- `src/path/proxy.c` — replace WinDivert loopback injection with MSTCP redirect: swap Eth+IP addresses, change conntrack entry B keys from LOOPBACK_ADDR to actual IPs, set revert action
- `src/path/return.c` — replace `addr->Outbound=0; WinDivertSend` with MSTCP delivery; update conntrack lookup keys from LOOPBACK_ADDR to actual IPs
- `src/path/bypass.c` — (signature change: `WINDIVERT_ADDRESS*` → ndisapi direction field)
- `src/dns/plan.c` — update all four DNS sub-cases (see below); replace WinDivertSend calls
- `src/dns/hijack.c` — update forwarder thread to build Ethernet header and use ndisapi MSTCP send; remove `divert_handle` storage
- `src/relay/tcp.c` — change bind address from `INADDR_LOOPBACK` to `INADDR_ANY`; update conntrack lookup keys from LOOPBACK_ADDR to actual peer IPs
- `src/relay/udp.c` — change bind address from `INADDR_LOOPBACK` to `INADDR_ANY`; change response `sendto()` destination from `client_ip:client_port` to `orig_dst_ip:client_port` so responses route through adapter for NDIS interception
- `src/conntrack/conntrack.c` — (no logic change; keys are supplied by callers which are already being updated)
- `src/app/main.c` — update subsystem init order, engine struct names, metrics names
- `src/app/config.c` — (no API change; config schema unchanged)
- `src/process/lookup.c` — remove WinDivert flow event watcher (`WINDIVERT_LAYER_FLOW`, `WinDivertOpen`/`WinDivertRecv`); keep background TCP/UDP table refresh only (already handles graceful degradation)
- `src/policy/rules.c` — (unchanged)
- `CMakeLists.txt` — remove WinDivert; add ndisapi import library; add new source files
- `README.md` — update driver requirements (WinDivert.sys → ndisrd.sys), build instructions
- `guide.md` — update architecture docs, runtime requirements

#### Removed files
- `inc/divert/adapter.h`
- `inc/divert/io.h`
- `src/divert/adapter.c`
- `lib/windivert/WinDivert.def`
- `lib/windivert/libWinDivert.a`
- `lib/windivert/windivert.h`

### DNS hijack adaptation (all four modes preserved)

| Mode | Outbound | Response delivery |
|---|---|---|
| UDP, non-loopback resolver | Rewrite dst → send to adapter (pass action) | Catch ON_RECEIVE → restore NAT → `SendPacketsToMstcpUnsorted` |
| UDP, loopback resolver | Socket forwarder (unchanged logic) | Build Ethernet+IP+UDP+DNS in forwarder thread → `SendPacketsToMstcpUnsorted`; dummy MACs acceptable |
| TCP, non-loopback resolver | Rewrite dst → send to adapter | Catch ON_RECEIVE → conntrack → restore → `SendPacketsToMstcpUnsorted` (same mechanism as regular TCP return) |
| TCP, loopback resolver | Rewrite src to dns_server_ip, dst to 127.0.0.1:redirect_port → MSTCP inject | Resolver response routes to dns_server_ip → adapter → NDIS catches ON_SEND → conntrack → restore → `SendPacketsToMstcpUnsorted` |

### ndisapi I/O model

- `OpenFilterDriver` → single driver handle stored in engine struct
- `GetTcpipBoundAdaptersInfo` → enumerate all adapters at startup
- For each adapter: `SetPacketEvent` + `SetAdapterMode(MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL)`
- N worker threads (default 4): each calls `ReadPacketsUnsorted` on shared event, processes batch inline, dispatches results via `SendPacketsToAdaptersUnsorted` or `SendPacketsToMstcpUnsorted`
- No pipeline queues between workers — batch API provides natural batching
- Filter all adapters unconditionally; no static filter table used (all classification is in user-mode)

### Packet flow (MSTCP revert model)

```
NDIS adapter captures ON_SEND packet
  → ReadPacketsUnsorted batch
  → packet_parse: extract eth, ip, tcp/udp headers
  → classify: determine traffic class from direction + ports/IPs
  → plan: decide action (pass/drop/rewrite/forward)
  
  For proxied TCP SYN:
    → conntrack add (keys use actual IPs, not LOOPBACK_ADDR)
    → swap Eth.src↔dst, swap IP.src↔dst
    → set TCP.dport = relay_port
    → recalculate checksums
    → SendPacketsToMstcpUnsorted (revert action)
    → OS delivers to relay listener

  For relay→client return:
    → relay listener sends data (INADDR_ANY-bound socket)
    → OS routes through adapter → NDIS captures ON_SEND
    → src_port == relay_port → TRAFFIC_CLASS_TCP_RETURN
    → conntrack lookup with actual IPs
    → restore original tuple
    → SendPacketsToMstcpUnsorted
    → OS delivers to client socket
```

### Conntrack key change

Current (WinDivert, two entries for TCP):
- Entry A: `(client_ip, client_port, server_ip, server_port)` — real tuple
- Entry B: `(LOOPBACK_ADDR, relay_src_port, LOOPBACK_ADDR, relay_port)` — loopback side

New (ndisapi, two entries for TCP):
- Entry A: `(client_ip, client_port, server_ip, server_port)` — unchanged
- Entry B: `(server_ip, relay_src_port, client_ip, relay_port)` — actual IPs, not loopback

For UDP: entry keys change from `(LOOPBACK_ADDR, src_port, ...)` to `(server_ip, src_port, ...)`.

### Relay listener bind change

- TCP relay: `bind(INADDR_LOOPBACK)` → `bind(INADDR_ANY)`
- UDP relay: `bind(INADDR_LOOPBACK)` → `bind(INADDR_ANY)`; response `sendto()` destination changes from `client_ip:client_port` → `orig_dst_ip:client_port` (looked up from conntrack).
  - Rationale: relay must accept MSTCP-injected connections addressed to client's local IP, and responses must route through external adapter for NDIS interception. For UDP, sending to the original server IP forces routing through the adapter.

### Direction model

| WinDivert | ndisapi |
|---|---|
| `addr->Outbound == 1` | `m_dwDeviceFlags & PACKET_FLAG_ON_SEND` |
| `addr->Outbound == 0` (inbound) | `m_dwDeviceFlags & PACKET_FLAG_ON_RECEIVE` |
| `addr->Loopback == 1` | Removed — no equivalent needed; MSTCP handles local delivery |
| `addr->Network.IfIdx` | `m_hAdapter` (adapter handle for send-to-adapter operations) |

### Type replacements

| Current | New |
|---|---|
| `PWINDIVERT_IPHDR` | `iphdr_ptr` (from `net/headers.h`) |
| `PWINDIVERT_TCPHDR` | `tcphdr_ptr` |
| `PWINDIVERT_UDPHDR` | `udphdr_ptr` |
| `WINDIVERT_ADDRESS` | Direction via `m_dwDeviceFlags`; adapter via `m_hAdapter` |
| `WinDivertHelperParsePacket` | Manual Ethernet→IP→TCP/UDP parsing in `packet_parse` |
| `WinDivertHelperCalcChecksums` | `RecalculateIPChecksum`, `RecalculateTCPChecksum`, `RecalculateUDPChecksum` |
| `WinDivertSend` | `SendPacketsToAdaptersUnsorted` or `SendPacketsToMstcpUnsorted` |

### Build system changes

- Cross-compile with Mingw from WSL2/Linux (unchanged)
- Replace `lib/windivert/libWinDivert.a` → ndisapi.dll import library
- Generate import library: `dlltool -d ndisapi.def -l libndisapi.a` (or use the DLL's .lib)
- Add `-I lib/ndisapi` include path
- Runtime: place `ndisapi.dll` and `ndisrd.sys` next to `WinTProxy.exe`
- Link flags: remove WinDivert, add ndisapi import lib

## Test strategy

### Key behaviors to test

1. **TCP proxying end-to-end:** Start proxy, curl a website → traffic flows through relay → SOCKS5 handshake → bytes relayed correctly
2. **UDP proxying end-to-end:** DNS query through proxy → SOCKS5 UDP ASSOCIATE → response received
3. **WSL/Hyper-V traffic:** curl from WSL → traffic intercepted → proxied (the primary motivation)
4. **DNS hijack — all four modes:**
   - UDP, external resolver (e.g., 8.8.8.8 → 127.0.0.1:1053)
   - UDP, loopback resolver (127.0.0.1:1053)
   - TCP, external resolver
   - TCP, loopback resolver
5. **Return path correctness:** Verify restored TCP sequence numbers, MSS clamping, IP addresses match original
6. **Self/loop protection:** Proxy traffic to itself not re-intercepted
7. **Multi-adapter:** Multiple network interfaces all filtered; adapter add/remove handled
8. **Conntrack cleanup:** Stale entries removed; pool exhaustion handled gracefully
9. **Checksum validation:** Post-rewrite packets verified with Wireshark/tshark
10. **Process lookup:** Per-process policy rules still match correctly

### Test approach

- Behavior-driven: test through public interfaces (start engine, inject test packets, verify actions)
- Packet-level correctness: capture before/after with pcap, verify headers
- Existing relay, conntrack, policy tests should pass unchanged (they're logic-preserving)

### Prior art

- Proxifyre's integration tests (if available in the repo)
- Existing WinTProxy manual test scenarios from `guide.md`

## Out of scope

- IPv6 support (passes through uninspected, same as current)
- SOCKS5 authentication (already not supported)
- Multiple SOCKS5 proxy endpoints (already single-proxy)
- Configurable adapter filtering (all adapters, unconditionally)
- Static filter table (all classification in user-mode)
- Pipeline threading model (simple multi-worker)
- WinDivert backward compatibility (complete removal)
- Deferred process resolution queue (Proxifyre pattern; may be needed later but not in initial migration)

## Further notes

- The ndisapi C API requires a Windows driver (`ndisrd.sys`) to be installed. This requires either test-signing mode (`bcdedit /set testsigning on`) or a WHQL-signed driver. The driver is available from `github.com/wiresock/ndisapi` releases.
- The `queued_multi_interface_packet_filter` C++ class from Proxifyre is NOT used. All filtering logic stays in WinTProxy's existing user-mode pipeline, adapted to ndisapi's C API.
- Proxifyre's `tcp_local_redirect` and `socks5_udp_local_redirect` C++ classes are NOT used. Their rewrite-and-revert logic is reimplemented in C within WinTProxy's existing `path/proxy.c` and `path/return.c`.
