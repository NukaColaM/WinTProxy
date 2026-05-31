# ndisapi adapter integration + basic pass-through

**Status**: complete
**Serial**: T1
**Spec**: ../specs/2026-05-30-ndisapi-migration.md
**Depends on**: T0 (none — this task stands alone)

> Stands alone. All subsequent tasks build on the adapter engine and packet parsing established here.

> **Done means**: WinTProxy compiles with ndisapi, starts up, enumerates adapters, captures packets, passes them through unmodified, and logs counters. Network traffic flows normally (transparent pass-through). WinDivert is removed from the build.

## Goal

Engine starts, captures all network traffic via ndisapi, and passes every packet through unmodified. Build system links against ndisapi.dll instead of WinDivert.

## Acceptance

- [x] `CMakeLists.txt` links against ndisapi import library; WinDivert entries removed
- [x] New files: `inc/ndisapi/adapter.h`, `src/ndisapi/adapter.c`, `inc/net/headers.h`, ndisapi vendored headers in `lib/ndisapi/`
- [x] `ndisapi_engine_t` struct holds: driver handle, adapter handles, running flag, workers, direction flag, counters
- [x] Adapter enumeration at startup: `GetTcpipBoundAdaptersInfo` → store all adapter handles
- [x] Per-adapter: `SetPacketEvent` + `SetAdapterMode(MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL)`
- [x] Worker thread: `ReadPacketsUnsorted` on shared event, processes batch inline (1 worker; unsorted API duplicates packets with multiple workers)
- [x] `packet_ctx_t` updated: uses `iphdr_ptr`/`tcphdr_ptr`/`udphdr_ptr` from `net/headers.h`; adds `ether_header_ptr`; no `WINDIVERT_ADDRESS`
- [x] `packet_parse` manually parses Ethernet→IPv4→TCP/UDP (replaces `WinDivertHelperParsePacket`)
- [x] `packet_recalculate_checksums` calls `RecalculateIPChecksum`/`RecalculateTCPChecksum`/`RecalculateUDPChecksum`
- [x] `traffic_action_t` uses ndisapi direction field instead of `WINDIVERT_ADDRESS*`
- [x] Worker loop: read batch → parse each packet → plan action → execute → `SendPacketsToAdaptersUnsorted` / `SendPacketsToMstcpUnsorted`
- [x] `src/app/main.c` updated: new engine struct names, init order
- [x] Old files removed: `inc/divert/adapter.h`, `inc/divert/io.h`, `src/divert/adapter.c`, `lib/windivert/*`
- [x] Compiles clean with `cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-toolchain.cmake && cmake --build build`
- [x] At runtime, logs show adapter count, driver version, running status, packet counters (recv/sent)

## Notes

- Worker count reduced from 4 to 1: the unsorted API delivers all pending packets to each caller, causing duplication with multiple workers. A per-worker event/queue model would be needed to scale.
- `INTERMEDIATE_BUFFER` has direction in `m_dwDeviceFlags` (`PACKET_FLAG_ON_SEND`/`PACKET_FLAG_ON_RECEIVE`). Pass-through sends ON_SEND packets to adapter and ON_RECEIVE packets to MSTCP.
- IP/TCP/UDP/ethernet header typedefs in `inc/net/headers.h`, adapted from Proxifyre's `iphlp.h`.
- The ndisapi vendor headers (`ndisapi.h`, `Common.h`) are in `lib/ndisapi/`.
- ndisapi import library: `dlltool -d ndisapi.def -l libndisapi.a`.
- The `ndisapi_engine_t` does NOT include `WINDIVERT_ADDRESS`. Direction is read from `INTERMEDIATE_BUFFER.m_dwDeviceFlags` per-packet. Adapter handle is `m_hAdapter` per-packet.
