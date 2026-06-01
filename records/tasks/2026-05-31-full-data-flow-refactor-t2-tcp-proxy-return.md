# TCP Proxy Return Path

**Status**: done
**Serial**: T2 (sequential within this spec -- T1, T2, T3...)
**Spec**: ../specs/2026-05-31-full-data-flow-refactor.md
**Depends on**: T1 (the flow-plan boundary and single execution owner must exist before TCP proxying can move onto it)

> TCP proxying is the first full stateful flow to prove that the new plan/execution split and conntrack contract still preserve the original behavior.

> **Done means**: all acceptance criteria pass, all tests pass. Change Status to `done` when met, or `dropped` with a reason if abandoned.

## Goal
Users can establish proxied TCP connections and receive replies through the restored return path under the new flow model.

## Acceptance
- [x] TCP proxy planning records the intended outcome without leaking mutable packet facts into later decisions.
- [x] TCP SYN and tracked non-SYN proxy traffic still reach the local relay and return to the client.
- [x] TCP return-path traffic uses named conntrack operations instead of caller-assembled tuple guessing.
- [x] TCP proxying still preserves the existing MSS clamp and proxy/direct policy behavior.
- [x] Tests cover proxied TCP setup, relay return traffic, and missing-state drop behavior.

## Notes
This slice likely touches the conntrack interface, TCP proxy path, return-path handling, relay/TCP behavior, and the common execution path.
