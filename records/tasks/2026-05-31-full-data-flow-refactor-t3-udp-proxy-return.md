# UDP Proxy Return Path

**Status**: done
**Serial**: T3 (sequential within this spec -- T1, T2, T3...)
**Spec**: ../specs/2026-05-31-full-data-flow-refactor.md
**Depends on**: T2 (the conntrack role model and TCP proxy return path must exist before UDP can reuse the same flow contract)

> UDP proxying proves the same flow model works for datagrams, not just TCP streams.

> **Done means**: all acceptance criteria pass, all tests pass. Change Status to `done` when met, or `dropped` with a reason if abandoned.

## Goal
Users can proxy UDP traffic and receive responses through the restored return path under the new flow model.

## Acceptance
- [x] UDP proxy planning records and uses the correct conntrack role state.
- [x] UDP datagrams still forward to the local relay and return without bypassing WinTProxy.
- [x] Missing or stale conntrack state fails closed instead of leaking direct traffic.
- [x] Tests cover UDP forward, relay response, and stale/missing state behavior.

## Notes
This slice likely touches the conntrack interface, UDP proxy path, return-path handling, relay/UDP behavior, and the common execution path.
