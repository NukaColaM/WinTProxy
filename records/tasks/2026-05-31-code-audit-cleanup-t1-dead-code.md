# Remove dead code and unused fields

**Status**: done
**Serial**: T1
**Spec**: ../specs/2026-05-31-code-audit-cleanup.md
**Depends on**: T0 (none — this task stands alone; removes code that no other task should touch)

> Foundation for all subsequent cleanup tasks. Nothing else should modify code that will be deleted.

> **Done means**: zero compiler warnings from dead code, no unused fields in structs, no dead functions or constants. Build is clean (only pre-existing warnings remain, if any).

## Goal

Strip all dead code — functions, struct fields, and constants that exist in the codebase but are never read or called.

## Acceptance

- [x] `src/process/lookup.c`: remove `flow_cache_put` function (line ~231); remove one `-Wunused-function` warning
- [x] `inc/process/lookup.h`: remove `flow_handle` and `flow_thread` fields from `proc_lookup_t`; remove references in `proc_lookup_init`/`proc_lookup_shutdown`
- [x] `inc/relay/udp.h`: remove `last_retry` field from `udp_session_t`; remove the line in `ensure_session` that sets it
- [x] `inc/core/constants.h`: remove `WTP_UDP_RETRY_DELAY_MS`; remove `UDP_RETRY_DELAY_MS` alias from `inc/relay/udp.h`
- [x] `src/path/classify.c`: remove `traffic_class_name` function (defined but never called, not in header)
- [x] Build with `cmake --build build` — zero warnings
- [x] `git grep flow_cache_put` returns zero hits
- [x] `git grep traffic_class_name` returns zero hits
- [x] `git grep last_retry` returns zero hits
- [x] `git grep WTP_UDP_RETRY_DELAY_MS` returns zero hits

## Notes

- `flow_handle` and `flow_thread` were set to INVALID_HANDLE_VALUE/NULL in `proc_lookup_init` and never used — removed fields and their initializer lines.
- `traffic_class_name` was standalone — no callers, no header declaration. Simply deleted.
