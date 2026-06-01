# Full Data Flow Refactor Questions

**Date**: 2026-05-31

## Questions
| # | Question | Answer |
|---|---|---|
| Q1 | Do you want this to be a full end-to-end data-flow redesign, or a narrower refactor around the packet pipeline seam? | Full end-to-end redesign of packet parsing, classification, planning, conntrack, DNS handling, and execution, while keeping relay internals and config parsing out of scope unless they need to change to support the new flow. |
| Q2 | Should the refactor introduce a new explicit `flow_plan`/`packet_rewrite` model where planning records the intended outcome first, and packet mutation happens later in one apply/execute step? | Yes. Classify and decide using immutable packet facts, produce an explicit plan, then apply rewrites, checksums, and send routing in one place. |
| Q3 | What is the compatibility requirement during the refactor: must each intermediate commit remain runnable, or can we do a larger branch-style rewrite that may be temporarily broken? | Larger branch-style rewrite. |
| Q4 | Which externally visible behaviors must stay the same after the rewrite? | Keep the config schema and CLI stable, preserve proxy/direct decision semantics, DNS-before-policy ordering, self/loop protection, and TCP/UDP return-path behavior. |
| Q5 | When the new planner cannot prove state for a packet, should the default be fail-open direct/pass or fail-closed drop? | Fail-closed for anything that would leak or corrupt state; no silent bypasses. Direct remains an explicit policy outcome for new observed flows, not an implicit fallback. |
| Q6 | Should any external traffic still be allowed to go direct, or should the new model treat all non-internal traffic as proxy-or-drop only? | Allow direct connections as a policy outcome, but discard preexisting external connections at startup so they cannot bypass WinTProxy. |
| Q7 | After startup, should direct traffic still be permitted by policy, or should WinTProxy proxy or drop everything new and treat “direct” only as a pre-startup exception cleanup mode? | Direct traffic remains permitted by policy after startup, but only for flows WinTProxy observes and classifies as direct; preexisting external flows are ignored or discarded. |

## Stories
1. As a maintainer, I want to redesign the entire packet data flow around one end-to-end pipeline, so that the migrated framework is stabilized instead of patched in place. ← Q1, Q3
2. As a maintainer, I want planning to produce an explicit flow plan before any packet mutation, so that rewrite logic and send routing happen in one audited step. ← Q2
3. As an operator, I want the refactor to preserve config, policy, DNS ordering, self/loop protection, and return-path semantics, so that the external behavior stays predictable. ← Q4
4. As a maintainer, I want undecided packets to fail closed whenever they could leak or corrupt state, so that unsafe flow transitions never bypass WinTProxy. ← Q5
5. As an operator, I want preexisting external connections discarded at startup while still allowing new direct decisions for observed flows, so that traffic established before WinTProxy cannot escape interception. ← Q6, Q7
