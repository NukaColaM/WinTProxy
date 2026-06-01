# Loopback DNS and TCP DNS

**Status**: done
**Serial**: T5 (sequential within this spec -- T1, T2, T3...)
**Spec**: ../specs/2026-05-31-full-data-flow-refactor.md
**Depends on**: T4 (the normal DNS rewrite path must exist before the loopback and TCP DNS variants can layer on their special handling)

> The loopback DNS path is the tricky one: it has its own forwarding and response injection behavior, and TCP DNS has its own conntrack return path.

> **Done means**: all acceptance criteria pass, all tests pass. Change Status to `done` when met, or `dropped` with a reason if abandoned.

## Goal
Users can resolve DNS through WinTProxy when the resolver is loopback-based or when DNS uses TCP.

## Acceptance
- [x] TCP DNS requests still redirect and return through conntrack restoration.
- [x] Loopback DNS forwarding still preserves the original query and restores the reply.
- [x] DNS self/loop protection still prevents DNS traffic from being routed back into a loop.
- [x] Tests cover loopback DNS and TCP DNS cases.

## Notes
This slice likely touches DNS hijack state, DNS forwarder behavior, conntrack return-path handling for DNS, and the common execution path. It is the highest-risk DNS slice, so it should expose any hidden assumptions early.
