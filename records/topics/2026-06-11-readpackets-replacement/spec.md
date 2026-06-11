# ReadPackets Replacement

**Status**: done

## Problem
WinTProxy's packet engine still centers on one shared `ReadPacketsUnsorted` worker and unsorted send helpers. That keeps the ingress path serialized and depends on a driver-queue model that is not documented as safe for concurrent readers. The current `ndisapi_engine_t` also exposes a shared packet event, per-worker unsorted pointer arrays, and send helpers that route through unsorted NDISAPI calls.

The project needs a no-fallback replacement that uses the documented adapter-associated `ReadPackets` queue model, while preserving the existing packet planning behavior, proxy/direct policy decisions, DNS-before-policy ordering, loopback DNS behavior, TCP/UDP return paths, and fail-closed safety defaults.

The replacement also changes buffer lifetime. `ReadPackets` fills caller-owned `INTERMEDIATE_BUFFER` structures, but phase 1 processing becomes asynchronous across adapter readers, flow workers, and sender threads. Readers cannot safely reuse packet buffers until downstream processing and send ownership has released them.

## Solution
Replace the current unsorted ingress with adapter-sharded `ReadPackets` readers. Each enumerated adapter gets its own packet event, read request, and reader loop. Readers obtain ref-counted packet blocks from a bounded shared pool, issue adapter-specific `ReadPackets`, and dispatch packets to bounded flow-affine worker queues.

Flow workers preserve per-flow ordering by routing the same adapter plus normalized IPv4 TCP/UDP tuple to the same worker. Different flows can run in parallel. Non-IP or unparseable packets are assigned by adapter and direction and remain pass-through unless existing planning rules say otherwise.

Driver sends move to dedicated batched sender threads that use adapter-specific `SendPacketsToAdapter` and `SendPacketsToMstcp` requests. The old `ReadPacketsUnsorted`, `SendPacketsToAdaptersUnsorted`, and `SendPacketsToMstcpUnsorted` production path is removed rather than kept as a fallback.

Phase 1 detects adapter-list changes and logs that restart is required. Dynamic adapter monitoring and live reader reconfiguration are phase 2 work.

## User stories
1. As a maintainer, I want to replace the shared `ReadPacketsUnsorted` ingress with adapter-sharded `ReadPackets` readers, so that packet intake has a documented per-adapter queue model and no unsorted fallback path. (Q1, Q4, Q8, Q12)
2. As a maintainer, I want adapter readers to hand packets to bounded flow-affine workers, so that per-flow ordering is preserved while different flows can run in parallel. (Q2, Q3, Q5, Q15, Q16)
3. As a maintainer, I want packet buffers to move through readers, workers, and senders with explicit ref-counted ownership, so that caller-owned NDIS buffers are not reused before downstream stages finish. (Q17, Q18)
4. As a maintainer, I want dedicated batched sender threads using adapter-specific NDISAPI send calls, so that flow workers do not block on driver I/O and the replacement avoids unsorted APIs. (Q7, Q8)
5. As an operator, I want overload, adapter-list changes, and shutdown to be explicit and bounded, so that drops, stale adapter state, and stop behavior are visible rather than implicit. (Q3, Q6, Q9, Q10, Q11, Q18)
6. As a maintainer, I want phase 1 verified through local build/static checks and a manual Windows smoke checklist, so that implementation can proceed in this workspace while acknowledging live-driver validation requirements. (Q13, Q19)

## Technical decisions
- Modify `inc/ndisapi/adapter.h` and `src/ndisapi/adapter.c` so `ndisapi_engine_t` owns adapter-reader contexts instead of one shared packet event and unsorted worker slices. Each adapter context includes the adapter handle, packet event, read thread handle, `ETH_M_REQUEST` storage, read buffers, and restart-required detection state.
- Remove production use of `ReadPacketsUnsorted`, `SendPacketsToAdaptersUnsorted`, and `SendPacketsToMstcpUnsorted`. The replacement must not contain a runtime fallback path to the unsorted APIs.
- Keep intercepting all enumerated adapters up to the existing adapter limit. For phase 1, adapter enumeration happens at start and adapter-list changes after start are detected and logged as restart-required.
- Add a bounded packet-block pool owned by `src/ndisapi`. Packet blocks contain `INTERMEDIATE_BUFFER` storage, parsed packet context storage, action storage as needed, adapter identity, direction, and a ref-counted ownership state used by readers, flow workers, and sender queues.
- Size flow workers from logical CPU count, clamped to 2..16. Give each flow worker a queue depth of 512 packet items. The pool and sender queue sizing should be derived from these bounds and the adapter read batch size rather than unbounded allocation.
- Define flow affinity as adapter handle plus normalized IPv4 TCP/UDP 5-tuple: protocol, lower endpoint, higher endpoint, and direction-insensitive endpoint ordering. For non-IP, unsupported protocol, or unparseable packets, use adapter handle plus packet direction so packets remain bounded and deterministic.
- Adapter readers wait on their adapter-specific packet event, acquire free packet blocks, issue `ReadPackets`, update receive counters, and enqueue each packet to the target flow worker. If a worker queue is full, the reader waits briefly, then drops the packet with counters and releases the block.
- If the free packet-block pool is exhausted before a reader can issue `ReadPackets`, the reader waits briefly. If capacity remains exhausted, it calls `FlushAdapterPacketQueue` for that adapter, increments explicit overload/drop counters, and logs the event with adapter identity.
- Keep packet planning in `src/flow` and `src/path` semantically compatible with the completed strong data-flow spec. The worker stage still calls `packet_parse`, `traffic_plan_packet`, and execution-equivalent logic; only thread ownership and send routing change.
- Change the executor/sender boundary in `inc/flow/executor.h`, `src/flow/executor.c`, and `inc/ndisapi/adapter.h` so flow workers enqueue send work rather than calling NDISAPI send helpers directly. Dedicated sender threads batch by adapter and target direction using `ETH_M_REQUEST` and adapter-specific `SendPacketsToAdapter` or `SendPacketsToMstcp`.
- Preserve `TRAFFIC_ACTION_FORWARD_UDP_TO_RELAY`, `TRAFFIC_ACTION_FORWARD_DNS_TO_RESOLVER`, and `TRAFFIC_ACTION_INJECT_DNS_RESPONSE` semantics. Any synthetic DNS response must enter the new sender path with the correct adapter handle and MSTCP target.
- Extend `ndisapi_counters_t` or add a compatible snapshot structure for overload drops, pool-exhaustion flushes, enqueue timeouts, adapter restart-required events, reader failures, and sender partial/failure counts. Existing packet received/sent/dropped/send-failure/UDP-forwarded counters remain available.
- Shutdown order for the replacement is: stop adapter readers, wake adapter events, stop cross-thread producers, drain accepted worker/sender work for a bounded interval, stop sender threads, reset adapter modes/events, free packet blocks, close driver and sockets. Repeated stop calls remain safe.
- Phase 1 does not implement dynamic adapter reader creation/removal after start. It may use adapter-list change notification or periodic comparison only to log restart-required state.
- Keep config schema and CLI unchanged. Worker count and queue depth are auto-sized internally and are not phase 1 config options.

## Test strategy
- Update local stubs so build/static tests can compile the adapter-specific contracts: `ReadPackets`, `SendPacketsToAdapter`, `SendPacketsToMstcp`, `FlushAdapterPacketQueue`, adapter events, thread waits, and packet-block ownership.
- Add unit-level tests for flow-affinity hashing so both directions of the same IPv4 TCP/UDP flow on the same adapter map to the same worker, while different adapters do not collide by key.
- Add queue/pool tests that verify bounded enqueue behavior, enqueue timeout drops, ref-count release, and pool-exhaustion adapter flush counters.
- Add sender contract tests that verify pass and rewrite actions become adapter-specific `ETH_M_REQUEST` sends batched by adapter and target direction, with no unsorted send APIs used by production code.
- Preserve existing flow behavior tests for pass, drop, rewrite/send, UDP relay forward, normal DNS rewrite, loopback DNS forwarding, TCP DNS, TCP proxy return, UDP proxy return, direct TCP, and fail-closed missing-state cases.
- Add shutdown tests for waking blocked readers, bounded drain of accepted work, sender thread stop, adapter event release, adapter mode reset, and repeated stop calls.
- Add static checks or targeted tests that fail if production `src` code still references `ReadPacketsUnsorted`, `SendPacketsToAdaptersUnsorted`, or `SendPacketsToMstcpUnsorted`.
- Include a manual Windows smoke checklist in the phase 1 task notes: install/load WinpkFilter, start WinTProxy, confirm per-adapter readers start, generate TCP/UDP/DNS traffic, verify counters move, verify no duplicate traffic under concurrent adapters, trigger adapter-list change and confirm restart-required log, then stop cleanly.

## Out of scope
- Runtime fallback to `ReadPacketsUnsorted`.
- Keeping unsorted send APIs in the production packet path.
- Dynamic adapter hot-plug reconfiguration in phase 1.
- Fast I/O or secondary Fast I/O sections.
- Config schema changes.
- CLI changes.
- IPv6 flow-affinity support beyond deterministic non-IPv4 fallback routing.
- Replacing WinpkFilter/NDISAPI.
- Changing proxy/direct policy semantics, DNS-before-policy ordering, startup quarantine behavior, self/loop protection, or fail-closed safety defaults.
- Broad relay protocol rewrites unrelated to the new packet ownership and sender boundary.

## Further notes
This spec is based on `questions.md` in this topic and the NDISAPI research record at `research/ndisapi-readpackets.md`.

The completed strong data-flow architecture spec remains the behavioral baseline for planning and execution semantics. This spec changes runtime ownership around ingress, queueing, buffer lifetime, and NDISAPI send routing.

Live driver behavior cannot be fully verified in this workspace. Local work should still compile and test the contracts, but final acceptance needs a Windows host with WinpkFilter installed and live adapter traffic.
