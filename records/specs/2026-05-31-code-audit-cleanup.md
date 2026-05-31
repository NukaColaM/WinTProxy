# Comprehensive code review and cleanup audit

**Status**: done

## Problem

The WinTProxy codebase has accumulated issues during the ndisapi migration (T1–T6) that need systematic resolution: dead code, unused fields, style inconsistencies, and potential runtime problems. A line-by-line audit is required to identify and fix all issues, producing a clean, consistent codebase for v0.7.x.

## Solution

Conduct a full audit across all source and header files, categorize findings by severity, and address them in a single cleanup pass. No functional changes — only dead-code removal, style unification, and minor correctness fixes.

## Technical decisions

### Modules to modify

All source files under `src/` and headers under `inc/`.

### Finding categories

#### P1 — Dead code and unused fields (must remove)

| # | File | Issue |
|---|------|-------|
| 1 | `src/process/lookup.c:231` | `flow_cache_put` — defined but never called; generates -Wunused-function warning |
| 2 | `inc/process/lookup.h:80-81` | `flow_handle` and `flow_thread` fields in `proc_lookup_t` — remnants of removed WinDivert flow watcher; always INVALID_HANDLE_VALUE/NULL |
| 3 | `inc/relay/udp.h:29` | `last_retry` in `udp_session_t` — written on creation but never read |
| 4 | `inc/core/constants.h:30` | `WTP_UDP_RETRY_DELAY_MS` — only used to set the unused `last_retry` field; dead constant |
| 5 | `src/path/classify.c:110` | `traffic_class_name()` — defined but never called; not declared in header |
| 6 | `inc/core/util.h:35` | `ipv4_net_to_host()` — used only in config parsing and policy matching, but defined in a util header that's included everywhere |

#### P2 — Style and consistency issues (should fix)

| # | File | Issue |
|---|------|-------|
| 7 | All `*.c` | Protocol numbers 6 (TCP) and 17 (UDP) used as raw literals in ~15 locations. Should use `IPPROTO_TCP`/`IPPROTO_UDP` or project constants |
| 8 | `src/dns/plan.c` | DNS planning functions use unusually compact style (multi-statement single lines, minimal braces). Inconsistent with rest of codebase |
| 9 | `src/path/proxy.c`, `src/path/return.c` | Ethernet MAC swap pattern (`uint8_t tmp[6]; memcpy...`) repeated 6 times. Extract into a helper |
| 10 | `inc/conntrack/conntrack.h`, `inc/relay/socks5.h`, `inc/app/config.h` | Missing `extern "C"` guards (others have them). Inconsistent |
| 11 | `inc/core/util.h`, `inc/process/lookup.h` | `#ifdef _WIN32` `#include <winsock2.h>` guards — project is Windows-only (ndisapi requires it). Guards are unnecessary noise |
| 12 | Various `.c` files | Mixed `//` and `/* */` comment styles. Pick one (project mostly uses `/* */` for block, `//` inline) |
| 13 | `inc/flow/action.h`, `inc/flow/plan.h` | Headers at the `flow/` level expose ndisapi types (`PINTERMEDIATE_BUFFER`) to callers that shouldn't need them. The `traffic_action_t` leaks implementation detail |
| 14 | `inc/core/constants.h` | Constants are prefixed `WTP_` but some are bare (`LOOPBACK_ADDR` in util.h). Inconsistent |

#### P3 — Potential issues and technical debt (consider)

| # | File | Issue |
|---|------|-------|
| 15 | `src/relay/tcp.c` | Connection pool: 8192 slots × ~128KB per connection = ~1 GB pre-allocated. `TCP_RELAY_CONN_MAX` should be reduced (128–512 reasonable) |
| 16 | `src/process/lookup.c` | `proc_lookup_refresh_locked` calls `flow_insert_locked` which acquires `flow_lock` — but `flow_cache_put` also acquires `flow_lock` exclusively. If `flow_cache_put` were ever called within the locked section it would deadlock (SRWLock is not recursive) |
| 17 | `src/relay/udp.c` | `handle_client_datagram` acquires `session_lock` exclusive, while `snapshot_relay_sockets` uses shared. The exclusive lock in the fast path could contend with the select-loop snapshot |
| 18 | All relay, proxy, dns files | `conntrack_get_full_key` copies an entry under shared lock, then the caller uses it. The cleanup thread could free the entry after the lock is released. Currently safe because the copy is used immediately and not referenced again, but fragile |
| 19 | `inc/ndisapi/adapter.h` | `NDISAPI_WORKER_COUNT = 1` — single worker may bottleneck under high throughput. The unsorted-API limitation is documented but a per-worker event model should be on the roadmap |

### Decisions

- **Protocol constants**: Replace raw `6`/`17` with `WTP_IPPROTO_TCP`/`WTP_IPPROTO_UDP` defined in `constants.h`. Do NOT use `IPPROTO_TCP` directly since it requires `<winsock2.h>` inclusion ordering which is fragile.
- **TCP relay pool size**: Reduce `WTP_TCP_RELAY_CONN_MAX` from 8192 to 512. This cuts pre-allocated memory from ~1 GB to ~64 MB, still more than enough for a transparent proxy.
- **Dead fields**: Remove `flow_handle`, `flow_thread` from `proc_lookup_t`; remove `last_retry` from `udp_session_t`; remove `flow_cache_put`; remove `traffic_class_name`; remove `WTP_UDP_RETRY_DELAY_MS`.
- **MAC swap**: Extract `swap_ether_addrs(ether_header_ptr)` inline helper in `net/headers.h`.
- **Style in dns/plan.c**: Expand compact statements to one-per-line with braces consistent with the rest of the codebase.
- **extern "C" guards**: Add to `conntrack/conntrack.h`, `relay/socks5.h`, `app/config.h`.
- **Win32 guards**: Leave as-is — they're harmless and the project may eventually add Linux test stubs.

### Out of scope

- Performance optimization (multi-worker, lock contention)
- Conntrack entry lifetime hardening
- IPv6 support
- Adding new features
- Changing the action model's type exposure

## Further notes

- The TCP relay pool size change (`8192 → 512`) is the only functional change in this cleanup. It reduces memory usage at startup. Operators with >512 concurrent proxied TCP connections would see connections rejected; this is extremely unlikely for a single-user transparent proxy.
- `ipv4_net_to_host` is reasonably placed in util.h since it's a general-purpose network utility. No action needed.
- The `_WIN32` guards and `#include <winsock2.h>` patterns are pervasive — removing them across ~20 files would be a large diff with no functional benefit. Deferred.
