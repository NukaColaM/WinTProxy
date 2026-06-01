# Full Data Flow Refactor

**Status**: active

## Problem
The current packet data flow is too complex to trust or change safely. Packet observation, classification, planning, mutation, conntrack role selection, DNS handling, and send routing are spread across multiple modules, and several of them share mutable packet state. That makes it hard to prove whether a packet will be passed, proxied, rewritten, or dropped, especially after the framework migration.

The result is not just readability debt. Correctness depends on callers knowing too many hidden contracts: when a packet context is still read-only, which conntrack role is being used, which path owns send routing, and when a packet is safe to forward versus safe to drop. The project needs a deeper data-flow structure before the migrated framework can be considered stable.

## Solution
Refactor the packet path into a clearer end-to-end flow with one explicit plan stage and one explicit execution stage. The new model should make packet facts immutable during decision-making, keep rewrite intent separate from packet mutation, and give send routing a single owner.

The refactor should preserve the existing external behavior that operators rely on: config and CLI shape, proxy/direct policy semantics, DNS-before-policy ordering, self/loop protection, and TCP/UDP return-path behavior. Direct traffic should still be allowed as an explicit policy result for newly observed flows, while preexisting external connections at startup should be discarded so they cannot bypass WinTProxy.

## User stories
1. As a maintainer, I want to redesign the entire packet data flow around one end-to-end pipeline, so that the migrated framework is stabilized instead of patched in place.  ← Q1, Q3
2. As a maintainer, I want planning to produce an explicit flow plan before any packet mutation, so that rewrite logic and send routing happen in one audited step.  ← Q2
3. As an operator, I want the refactor to preserve config, policy, DNS ordering, self/loop protection, and return-path semantics, so that the external behavior stays predictable.  ← Q4
4. As a maintainer, I want undecided packets to fail closed whenever they could leak or corrupt state, so that unsafe flow transitions never bypass WinTProxy.  ← Q5
5. As an operator, I want preexisting external connections discarded at startup while still allowing new direct decisions for observed flows, so that traffic established before WinTProxy cannot escape interception.  ← Q6, Q7

## Technical decisions
- Modify the packet context and packet parsing modules so the observed packet facts and rewrite state are no longer treated as one thing.
- Introduce an explicit flow-plan layer that records the intended outcome before any packet mutation occurs.
- Consolidate send routing behind one execution path instead of splitting it across the worker loop, executor, and DNS forwarder.
- Rework the conntrack interface so flow-role lookups and return-path restoration are named operations rather than caller-assembled tuple access.
- Rework DNS handling so DNS queries, NAT state, and loopback forwarding fit the same plan/execute model as other traffic.
- Keep the config schema and CLI stable.
- Keep proxy/direct policy semantics stable, including explicit direct decisions for new observed flows.
- Keep DNS-before-policy ordering stable.
- Keep self/loop protection stable.
- Keep TCP and UDP return-path behavior stable.

## Test strategy
- Exercise the new packet-flow boundary through the public engine path, not by unit-testing internal mutations in isolation.
- Verify that observed packet facts remain stable through planning and that mutations happen only in the execution stage.
- Verify that proxy, direct, DNS, self, loopback, and return-path cases produce the same external behavior as before.
- Verify startup behavior around preexisting external connections, new direct flows, and flows that cannot be proven safe.
- Add tests around conntrack role selection, DNS handling, and send routing because those are the places where hidden state has been hardest to reason about.

## Out of scope
- Relay protocol internals beyond what is needed to support the new flow model.
- Config schema changes.
- CLI changes.
- IPv6 support.
- Replacing the SOCKS5 proxy architecture.
- Changing the external policy model away from proxy/direct decisions.

## Further notes
The clarify session left one tension resolved in favor of a narrower compatibility boundary: direct traffic remains a valid policy result after startup, but only for newly observed flows. Preexisting external connections are to be discarded so they cannot become a bypass channel.

The refactor is intentionally larger than a local cleanup. The important deliverable is a shallower packet-flow architecture with fewer hidden state transitions, not a line-by-line preservation of the current module boundaries.
