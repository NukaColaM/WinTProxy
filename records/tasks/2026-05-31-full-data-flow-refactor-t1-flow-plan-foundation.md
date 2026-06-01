# Explicit Flow-Plan Foundation

**Status**: done
**Serial**: T1 (sequential within this spec -- T1, T2, T3...)
**Spec**: ../specs/2026-05-31-full-data-flow-refactor.md
**Depends on**: T0 (none -- this task stands alone)

> The packet-plan seam and single execution path need to exist before any proxy, DNS, or startup quarantine work can be trusted in the new model.

> **Done means**: all acceptance criteria pass, all tests pass. Change Status to `done` when met, or `dropped` with a reason if abandoned.

## Goal
Users can still start WinTProxy and have direct, bypass, and drop decisions travel through one explicit flow-plan boundary instead of being split across multiple send paths.

## Acceptance
- [x] The packet path produces one explicit plan record before packet mutation happens.
- [x] Packet facts used for planning stay stable until execution applies the chosen outcome.
- [x] Direct/pass, bypass, and drop outcomes all go through one execution owner.
- [x] Existing direct traffic still passes and non-proxyable traffic still exits on the correct path after the refactor.
- [x] Tests cover one direct flow, one non-proxyable flow, and one drop case through the public engine path.

## Notes
This is the structural base for the rest of the refactor. It likely touches the packet context, flow model, classifier, executor, and adapter worker path, but it should still deliver visible traffic behavior on its own.
