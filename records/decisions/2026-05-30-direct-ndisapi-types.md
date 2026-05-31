# Use ndisapi types directly (no abstraction layer)

**Date**: 2026-05-30

## Context

WinTProxy currently uses WinDivert-specific types throughout the codebase: `PWINDIVERT_IPHDR`, `PWINDIVERT_TCPHDR`, `PWINDIVERT_UDPHDR`, `WINDIVERT_ADDRESS`. When replacing WinDivert with ndisapi, we must adopt ndisapi's types from `Common.h`: `iphdr_ptr`, `tcphdr_ptr`, `udphdr_ptr`, `ether_header_ptr`, and the `INTERMEDIATE_BUFFER` metadata struct. The question was whether to wrap these behind neutral typedefs (abstraction layer) or use them directly.

## Decision

**Replace WinDivert types with ndisapi types directly throughout the entire codebase.** Do not introduce a typedef-based abstraction layer.

## Why not alternatives

- **Abstraction layer (neutral typedefs, e.g., `pkt_ip_hdr_t`)** — rejected because:
  - The mapping is 1:1 and unchanging (we're not swapping packet engines again).
  - An abstraction hides critical ndisapi semantics that pipeline code needs to understand (e.g., `m_dwDeviceFlags` for direction, `m_hAdapter` for per-interface routing).
  - Debugging suffers: core dumps show raw ndisapi field values, and an indirection layer forces mental translation.
  - Doubles the learning surface: developers must know both the abstraction and the underlying types.
  - The migration is one-time; the maintenance cost of indirection is permanent.
