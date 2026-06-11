# Full Data Flow Refactor Research

**Date**: 2026-05-31
**Prompted by**: Q1-Q3

## What was investigated
- Traced the packet path from `src/ndisapi/adapter.c` through `src/path/classify.c`, `src/flow/plan.c`, `src/path/*`, `src/dns/plan.c`, `src/flow/executor.c`, and the relay modules.
- Checked how packet state, conntrack, DNS NAT, and relay delivery are represented and mutated.
- Reviewed the startup lifecycle in `src/app/main.c` and the state tables in conntrack, process lookup, and DNS hijack.

## Findings
- `packet_ctx_t` is both a parsed observation and a mutable rewrite handle.
- Send routing is split across the worker loop, the executor, and the DNS forwarder.
- Conntrack entries encode multiple roles in one structure, so callers need to know whether they are using entry A, entry B, or a return-path snapshot.
- DNS loopback handling injects its own MSTCP frame path, separate from the normal executor flow.
- The startup sequence initializes conntrack, process lookup, DNS hijack, relays, and NDIS capture before traffic processing starts.

## Implications
- The refactor should center an immutable packet observation plus an explicit planned outcome.
- Send routing should have one owner.
- Conntrack and DNS state should be hidden behind role-specific operations instead of caller-assembled tuple contracts.
