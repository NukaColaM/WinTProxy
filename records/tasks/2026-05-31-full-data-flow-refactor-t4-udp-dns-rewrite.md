# UDP DNS Rewrite

**Status**: done
**Serial**: T4 (sequential within this spec -- T1, T2, T3...)
**Spec**: ../specs/2026-05-31-full-data-flow-refactor.md
**Depends on**: T3 (the UDP flow contract and execution path must already exist before DNS can reuse them safely)

> Normal DNS is the first special-case path that has to fit the new model without bypassing it.

> **Done means**: all acceptance criteria pass, all tests pass. Change Status to `done` when met, or `dropped` with a reason if abandoned.

## Goal
Users can resolve DNS through WinTProxy for normal UDP resolvers under the new plan/execution model.

## Acceptance
- [x] UDP DNS traffic is planned before policy and handled through the new flow-plan boundary.
- [x] UDP DNS queries still rewrite and restore correctly for normal resolvers.
- [x] DNS send routing uses the common execution path instead of a separate bypass.
- [x] Tests cover UDP DNS rewrite and DNS response restoration.

## Notes
This slice likely touches DNS planning, DNS NAT, packet context payload handling, the common executor, and the adapter send path.
