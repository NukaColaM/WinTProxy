# Shutdown Fence

**Status**: done
**Serial**: T7
**Spec**: ../spec.md
**Depends on**: T6

> Shutdown is part of the data-flow boundary: packet interception must stay up
> until relay-owned links have been closed, so relay traffic cannot escape the
> WinTProxy path during teardown.

> **Done means**: all acceptance criteria pass, all tests pass. Change Status to
> `done` when met, or `dropped` with a reason if abandoned.

## Goal
Stopping WinTProxy closes relay-owned TCP/UDP traffic before packet interception
is disabled.

## Acceptance
- [x] TCP relay shutdown happens before `ndisapi_stop`.
- [x] UDP relay shutdown happens before `ndisapi_stop`.
- [x] The app shutdown path uses one explicit lifecycle helper for subsystem
      stop ordering.
- [x] Tests cover the shutdown ordering that prevents relay traffic leaks.

## Notes
2026-06-01: Trace showed `ndisapi engine stopped` before active TCP relay
connections were closed, leaving a teardown window where relay traffic could
outlive packet interception. The app now stops TCP/UDP relays before stopping
ndisapi, and `tcp_relay_stop` closes active TCP connections before waiting on
the sleeping conntrack refresh thread.
