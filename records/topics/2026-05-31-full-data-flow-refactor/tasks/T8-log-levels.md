# Logging Signal Cleanup

**Status**: done
**Serial**: T8
**Spec**: ../spec.md
**Depends on**: T7

> The data-flow refactor is only operable if normal debug logs show routing
> decisions without requiring packet-level trace logging.

> **Done means**: all acceptance criteria pass, all tests pass. Change Status to
> `done` when met, or `dropped` with a reason if abandoned.

## Goal
Make route-level logging useful without flooding the async logger during normal
debug runs.

## Acceptance
- [x] Policy route decisions are visible at debug level.
- [x] Bypass/direct pass decisions are visible at debug level.
- [x] Idle DNS forwarder receive timeouts and shutdown socket interrupts are
      treated as normal control flow, not emitted as per-second trace noise.
- [x] Packet-level rewrite details remain trace-level.
- [x] Tests cover the level placement for the changed data-flow log events.

## Notes
2026-06-01: Fresh trace logs showed 18,118 TRACE lines, 471 DEBUG lines, and two
logger drop warnings. The largest source was packet-level return rewrite tracing,
which should stay trace-only. The actionable misleveling was route decisions and
normal DNS forwarder receive timeouts.

2026-06-01: Policy and bypass route decisions now emit at debug level. DNS
forwarder receive timeout, interrupt, and closed-socket errors are classified as
normal silent control flow. Packet rewrite traces are unchanged.
