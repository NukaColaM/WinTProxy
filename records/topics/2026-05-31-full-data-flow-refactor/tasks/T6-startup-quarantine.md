# Startup Quarantine

**Status**: done
**Serial**: T6 (sequential within this spec -- T1, T2, T3...)
**Spec**: ../spec.md
**Depends on**: T5 (the startup sweep should be evaluated against the final packet-flow model, not an intermediate one)

> Startup behavior is the last safety boundary: preexisting external connections must not survive as a bypass channel once WinTProxy comes up.

> **Done means**: all acceptance criteria pass, all tests pass. Change Status to `done` when met, or `dropped` with a reason if abandoned.

## Goal
Users starting WinTProxy do not keep preexisting external connections alive as a bypass channel, while new direct decisions for observed flows still work.

## Acceptance
- [x] Startup handling identifies or discards preexisting external connections before they can escape interception.
- [x] New flows observed after startup still receive normal direct or proxy decisions.
- [x] Direct TCP flows observed from SYN after startup keep passing subsequent non-SYN packets.
- [x] Loopback and other internal control traffic still works.
- [x] Tests or a reproducible integration check cover the startup boundary.

## Notes
This slice likely touches the application lifecycle, startup flow classification, and the state tables that distinguish old external traffic from newly observed traffic.

2026-06-01 follow-up: DNS failure trace showed direct `mihomo.exe` TCP SYNs were allowed but later packets on the same direct flow were quarantined as preexisting. The fix records direct TCP SYNs in conntrack with no relay port and passes later packets that match that post-startup direct state.
