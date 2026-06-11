# ReadPackets Replacement Questions

**Date**: 2026-06-11

## Questions
| # | Question | Answer |
|---|---|---|
| Q1 | Should the target architecture be an adapter-sharded `ReadPackets` replacement for the current shared `ReadPacketsUnsorted` ingress? | Replace the current ingress with adapter-sharded `ReadPackets`; do not provide a runtime fallback to `ReadPacketsUnsorted`. |
| Q2 | After each adapter-specific `ReadPackets` reader drains packets, where should packet processing happen? | Adapter readers dispatch packet work to bounded flow-affine worker queues. |
| Q3 | When a flow-affine worker queue is full, what should the reader do with newly drained packets? | Wait briefly for enqueue capacity, then drop with explicit counters if the queue remains full. |
| Q4 | Should the `ReadPackets` replacement keep intercepting every enumerated adapter, or narrow to selected adapters? | Intercept all enumerated adapters, matching the current broad unsorted-reader scope. |
| Q5 | What ordering guarantee should the new architecture preserve? | Preserve per-flow ordering; parallelism across different flows is allowed. |
| Q6 | How should shutdown handle packets already queued in user-mode workers? | Drain accepted user-mode work briefly, then stop rather than waiting indefinitely. |
| Q7 | Should send-back to NDISAPI happen inside each flow worker, or through dedicated sender threads? | Use dedicated sender threads with batching. |
| Q8 | Should the dedicated sender path preserve adapter-specific `SendPacketsToAdapter`/`SendPacketsToMstcp`, or convert output back to unsorted send APIs? | Use adapter-specific send APIs and avoid unsorted send APIs in the replacement architecture. |
| Q9 | What should happen to adapter hot-plug or adapter-list changes in this replacement? | Dynamic adapter monitoring is required, but it belongs to phase 2 rather than phase 1. |
| Q10 | For phase 1, should the implementation explicitly detect adapter-list changes and log "restart required," while leaving dynamic monitoring as phase 2 scope? | Yes. Phase 1 should detect adapter-list changes and log that restart is required. |
| Q11 | Should phase 1 include a runtime/threading self-test or instrumentation to detect duplicate, reordered, or dropped packet handling during development? | Add counters and debug logs only; do not build a full packet harness in phase 1. |
| Q12 | Should the old `ReadPacketsUnsorted` implementation be removed from production code during phase 1, or left compiled but unreachable? | Remove the old unsorted production ingress; no fallback should remain. |
| Q13 | What should count as phase 1 verification if this workspace cannot run the Windows NDISAPI driver? | Use build/static verification plus a manual Windows smoke checklist for live-driver validation. |
| Q14 | How should phase 1 choose the number of flow workers and queue sizes? | Auto-size from CPU count rather than using static compile-time tunables or config options. |
| Q15 | What auto-sizing policy should phase 1 use for flow workers and queue depth? | Use conservative bounds: worker count equals logical CPU count clamped to 2..16, with queue depth of 512 packets per worker. |
| Q16 | What should define "same flow" for flow-affine worker dispatch? | Use adapter plus normalized L3/L4 5-tuple; assign non-IP or unparseable packets by adapter and direction. |
| Q17 | How should packet buffer ownership work across reader, flow worker, and sender threads? | Use ref-counted packet blocks from a bounded shared pool so readers cannot reuse buffers still owned by downstream stages. |
| Q18 | If the shared packet-block pool is exhausted before an adapter reader can issue `ReadPackets`, what should happen? | Wait briefly for a free block, then flush that adapter queue with explicit counters under sustained exhaustion. |
| Q19 | Should phase 1 write a durable `questions.md` record and then move directly into a spec for implementation? | Yes. Record the clarified requirements, remove the superseded unimplemented spec, then use `spec` next. |

## Stories
1. As a maintainer, I want to replace the shared `ReadPacketsUnsorted` ingress with adapter-sharded `ReadPackets` readers, so that packet intake has a documented per-adapter queue model and no unsorted fallback path. (Q1, Q4, Q8, Q12)
2. As a maintainer, I want adapter readers to hand packets to bounded flow-affine workers, so that per-flow ordering is preserved while different flows can run in parallel. (Q2, Q3, Q5, Q15, Q16)
3. As a maintainer, I want packet buffers to move through readers, workers, and senders with explicit ref-counted ownership, so that caller-owned NDIS buffers are not reused before downstream stages finish. (Q17, Q18)
4. As a maintainer, I want dedicated batched sender threads using adapter-specific NDISAPI send calls, so that flow workers do not block on driver I/O and the replacement avoids unsorted APIs. (Q7, Q8)
5. As an operator, I want overload, adapter-list changes, and shutdown to be explicit and bounded, so that drops, stale adapter state, and stop behavior are visible rather than implicit. (Q3, Q6, Q9, Q10, Q11, Q18)
6. As a maintainer, I want phase 1 verified through local build/static checks and a manual Windows smoke checklist, so that implementation can proceed in this workspace while acknowledging live-driver validation requirements. (Q13, Q19)
