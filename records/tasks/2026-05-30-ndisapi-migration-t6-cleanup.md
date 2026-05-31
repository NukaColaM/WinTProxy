# Cleanup, docs, final removal of WinDivert references

**Status**: done
**Serial**: T6
**Spec**: ../specs/2026-05-30-ndisapi-migration.md
**Depends on**: T5 (all DNS modes must be working before docs describe them as features)

> Removes all remaining WinDivert references from the codebase, updates documentation to reflect ndisapi requirements, and ensures a clean build with no stale artifacts.

> **Done means**: No WinDivert references remain in source, headers, build files, or documentation. README and guide accurately describe ndisapi setup.

## Goal

Repository is clean of WinDivert references. Documentation accurately describes ndisapi-based operation.

## Acceptance

- [x] Remove all `#include "windivert/windivert.h"` from source files (already removed in T1; process/lookup.c cleaned in T3; confirmed zero remaining)
- [x] Remove `lib/windivert/` directory entirely (headers, .def, .a) — already removed in T1
- [x] Grep for `windivert`, `WinDivert`, `WINDIVERT` across all source, headers, cmake, and docs — no hits (except records/)
- [x] `README.md` updated:
  - Remove WinDivert runtime requirements (WinDivert.dll, WinDivert64.sys)
  - Add ndisapi runtime requirements (ndisapi.dll, ndisrd.sys)
  - Remove refactoring notice banner
  - Update Quick Start: driver installation instructions (test-signing mode or signed driver)
  - Update third-party license section
- [x] `guide.md` updated:
  - Architecture diagram: `src/divert/` → `src/ndisapi/`
  - Packet flow: ndisapi adapter, Ethernet layer + MSTCP revert model
  - TCP proxy: WinDivert loopback injection → MSTCP revert
  - UDP proxy: loopback response → adapter-routed response
  - DNS loopback: WinDivert injection → MSTCP injection
  - Process lookup: WinDivert flow events → owner-table polling
  - Subsystem lifecycle: Divert adapter → ndisapi engine
- [x] `CMakeLists.txt`: confirmed no WinDivert entries, correct ndisapi library path
- [x] Config schema documentation: no changes needed (schema unchanged)
- [x] `config.example.json`: no WinDivert-specific notes
- [x] Full build succeeds
- [x] `git status` shows intended changes only
- [x] `WTP_DIVERT_*` constants removed from `constants.h` (unused; ndisapi tunables live in `inc/ndisapi/adapter.h`)
- [x] `WINTPROXY_VERSION` bumped to v0.7.0 (minor — backend migration)
- [x] All WinDivert-mentioning comments rewritten or removed from source and headers

## Notes

- `flow_cache_put` in `src/process/lookup.c` is unused (left for potential future use; generates one warning). The WinDivert flow-event watcher was already removed in T3.
- The ndisapi import library (`lib/ndisapi/libndisapi.a`) is generated via `dlltool` per the CMakeLists.txt build instructions.
