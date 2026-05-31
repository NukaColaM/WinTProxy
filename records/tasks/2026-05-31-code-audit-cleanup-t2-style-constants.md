# Unify style: protocol constants, MAC helper, formatting

**Status**: done
**Serial**: T2
**Spec**: ../specs/2026-05-31-code-audit-cleanup.md
**Depends on**: T1 (dead code must be removed first so style changes don't touch code that will be deleted)

> Standardizes repeated patterns and magic numbers across the codebase. Every file that uses raw protocol numbers or duplicates the MAC swap gets cleaned.

> **Done means**: no raw `6` or `17` as protocol identifiers remain; MAC swap uses a single shared helper; dns/plan.c matches project formatting; extern "C" guards are consistent.

## Goal

Replace magic numbers with named constants, extract repeated code into helpers, normalize formatting in outlier files, and add missing extern "C" guards.

## Acceptance

- [x] **Protocol constants**: add `WTP_IPPROTO_TCP 6` and `WTP_IPPROTO_UDP 17` to `inc/core/constants.h`
- [x] Replace all raw `6` (TCP) protocol literals in `.c` files with `WTP_IPPROTO_TCP`:
  - `src/path/proxy.c` (2 sites: conntrack lookup + relay_port check)
  - `src/path/return.c` (proto_num initialization)
  - `src/process/lookup.c` (3 sites: append_record + 2 proc_lookup_flow calls)
  - `src/dns/plan.c` (2 sites: conntrack get + add_key_full)
  - `src/relay/tcp.c` (4 sites: conntrack touch + lookup)
- [x] Replace all raw `17` (UDP) protocol literals:
  - `src/path/return.c` (proto_num initialization)
  - `src/process/lookup.c` (3 sites: append_record + 2 proc_lookup_flow calls)
  - `src/relay/udp.c` (2 sites: conntrack get + get_full)
- [x] **MAC swap helper**: add `static inline void swap_ether_addrs(ether_header_ptr eth)` to `inc/net/headers.h`
- [x] Replace all 5 manual MAC swap blocks in `src/path/proxy.c`, `src/path/return.c`, and `src/dns/plan.c` with calls to `swap_ether_addrs`
- [x] **dns/plan.c style**: expanded compact multi-statement lines to one-statement-per-line with braces matching project norm
- [x] **extern "C" guards**: added `#ifdef __cplusplus extern "C" { #endif` / `#ifdef __cplusplus } #endif` to:
  - `inc/conntrack/conntrack.h`
  - `inc/relay/socks5.h`
  - `inc/app/config.h`
- [x] Build with `cmake --build build` — zero warnings
- [x] Grep confirms: 13 WTP_IPPROTO_TCP usages, 7 WTP_IPPROTO_UDP usages, 6 swap_ether_addrs calls, 0 manual MAC swap blocks

## Notes

- `WTP_IPPROTO_TCP`/`WTP_IPPROTO_UDP` chosen over raw `IPPROTO_TCP` to avoid winsock2 include-ordering fragility.
- MAC swap helper placed in `net/headers.h` since it operates on `ether_header_ptr`.
- Raw protocol numbers in packet construction code (`src/packet/context.c`, `src/dns/hijack.c`) left as-is — they compare against on-wire IP header values.
- Total: 20 raw protocol literals replaced across 5 files, 5 MAC swap blocks replaced.
