# Memory and safety improvements

**Status**: done
**Serial**: T3
**Spec**: ../specs/2026-05-31-code-audit-cleanup.md
**Depends on**: T2 (style changes must be complete to avoid touching the same lines twice)

> The highest-impact changes: reduce the TCP relay connection pool from 1 GB to ~64 MB, and add safety documentation for conntrack entry lifetimes.

> **Done means**: TCP relay pre-allocates a reasonable memory pool; remaining P3 findings are addressed or documented as deferred.

## Goal

Reduce startup memory from ~1 GB to ~64 MB by shrinking the TCP relay connection pool. Document conntrack entry lifetime and lock-ordering constraints.

## Acceptance

- [x] **TCP relay pool**: changed `WTP_TCP_RELAY_CONN_MAX` in `inc/core/constants.h` from `8192` to `512` (~1 GB → ~64 MB at startup)
- [x] **Conntrack safety comment**: added comment above lookup functions in `inc/conntrack/conntrack.h` documenting snapshot-copy semantics and lifetime contract
- [x] **proc_lookup lock ordering**: added comment in `proc_lookup_refresh_locked` documenting lock ordering: `refresh_lock → flow_lock → pid_lock`
- [x] **UDP ensure_session review**: verified exclusive lock only taken on slow path (new session / ctrl_sock cleanup); added TODO for per-bucket locking if contention ever becomes measurable
- [x] **traffic_action_t exposure**: added comment in `inc/flow/action.h` documenting intentional leak of `PINTERMEDIATE_BUFFER` for hot-path performance
- [x] Build with `cmake --build build` — zero warnings

## Notes

- TCP pool reduction is the only runtime-behavior change in the entire audit. 512 concurrent connections is more than sufficient for a single-user transparent proxy.
- Conntrack entry copy pattern verified safe under current usage — all callers consume the copy immediately.
- Remaining P3 findings (constant prefixing, ndisapi worker count, single-worker bottleneck) are documented as known tradeoffs, not bugs.
