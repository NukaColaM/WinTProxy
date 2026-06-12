# Hot-Path Consolidation

**Status**: done

## Problem
The 2026-06-11 structure review of the completed readpackets-replacement and strong-data-flow specs found five frictions where the two refactors meet.

The batch unit dissolved between them: flow workers plan and execute one packet at a time through a batch-shaped executor, so every packet pays per-packet queue locks and event wakes at the reader-to-worker and worker-to-sender hops, the executor builds 2x256 send arrays per single action, senders heap-allocate the send request per flush, and packet blocks are cleared twice per pool cycle. Conntrack keep-alive choreography is spread across the return-path planner, both relays, and a periodic refresh thread: a proxied TCP return packet costs three bucket-lock round trips and a full-entry snapshot including a 256-byte process name, the TCP relay touches entries per recv completion despite its own 20s refresh thread against a 60s TTL, and outbound proxied UDP re-runs process lookup, policy, and a double conntrack upsert on every datagram. The packet pool is smaller than the queues it feeds, so one stalled stage absorbs the pool and pushes readers into Sleep(1) timer-quantum loops before a wholesale adapter queue flush. Untracked non-SYN TCP packets trigger a synchronous owner-table rebuild on a flow worker even though identity cannot change their disposition. The UDP relay spends three liveness syscalls and an exclusive lock per datagram.

Two adjacent defects surfaced while structuring this spec: adapter readers read at most one batch per event wake, stranding burst backlogs until the next arrival or the 100ms timeout; and the executor-to-relay UDP frame omits the destination, so the relay recovers it from the latest conntrack upsert - datagrams from one client port to multiple destinations can be wrapped toward, and responses attributed to, the wrong server.

## Solution
Make the read batch the unit of work through plan and execution, finish the conntrack role contract so lookup and liveness are one fused conntrack-owned operation, derive pool and queue sizing from a single in-flight capacity model with event-based waits, stop paying identity costs where identity cannot change the outcome, carry the destination in UDP relay frames so multi-destination UDP routes correctly, and strip per-datagram syscalls from the UDP relay loop.

Operator-visible behavior is preserved: config and CLI shape, DNS-before-policy ordering, proxy/direct policy semantics (now correct per destination for UDP), self/loop protection, startup quarantine, fail-closed defaults, and TCP/UDP return-path behavior.

## User stories
1. As a maintainer, I want flow workers to drain, plan, and execute read batches as batches, so that queue locks, event wakes, and send flushes amortize across the batch instead of repeating per packet.
2. As a maintainer, I want conntrack role operations that fuse lookup with TTL refresh and own entry-pair liveness, so that planners and relays stop choreographing touches and stop copying process names on per-packet paths.
3. As an operator, I want pool and queue sizes derived from one in-flight capacity model with event-based waits, so that bursts shed the newest packets instead of stalling on timer quanta and flushing the driver queue.
4. As a maintainer, I want planners to consult process identity only where it can change the packet's disposition, so that a dead flow's retransmits cannot head-of-line block a flow worker on owner-table rebuilds.
5. As an operator, I want UDP relay frames to carry each datagram's destination and responses to be attributed to their actual source server, so that one client port talking to several servers is proxied correctly in both directions.
6. As an operator, I want the UDP relay datagram path free of per-datagram liveness probes and exclusive locks, so that the single relay thread stays viable at higher session counts.

## Technical decisions
- Batch unit. Modify `src/ndisapi/adapter.c` so flow workers drain-dequeue queued blocks (up to `NDISAPI_BATCH_SIZE`) per wake, parse and plan each into block-owned storage, then execute the drained set through one `traffic_execute_actions` call; FIFO order within a worker preserves per-flow ordering. Adapter readers group blocks by target worker per read batch and enqueue each group with one queue lock and one wake per worker; the flow-worker enqueue contract in `inc/ndisapi/adapter.h` becomes multi-block.
- Executor flush. `src/flow/executor.c` keeps target-grouped send arrays; with real batches, sender enqueue is one sender-queue lock and wake per target per executor flush. Drops and socket-forward actions remain explicit per-action outcomes inside the batch loop.
- Sender allocation. Each `ndisapi_sender_t` owns preallocated `ETH_M_REQUEST` storage and grouping scratch sized for `NDISAPI_BATCH_SIZE`; no heap allocation per flush.
- Block hygiene. Packet blocks are cleared exactly once per pool cycle, at the point of use: `ReadPackets` fills the buffer, `packet_parse` clears the context, and action constructors clear the action (refined during T3 from release-path clearing - use-time clearing is strictly fewer writes since parse and constructors already clear unconditionally). Acquire sets identity fields only; the `INTERMEDIATE_BUFFER` is never pre-cleared and `m_Length` governs validity.
- Reader drain. Readers repeat ReadPackets while it returns a full batch before re-waiting on the packet event, so burst backlogs are not stranded behind the 100ms wait.
- Capacity model. Pool capacity is derived at start from reader in-flight batches (adapters x batch x 2) plus total flow-queue depth plus total sender-queue depth, with the driver-side SetPoolSize aligned to reader in-flight. Pool-exhaustion and enqueue waits become waitable-event waits (pool free-space event, per-worker space event) with the existing bounded-wait, drop-newest, and `FlushAdapterPacketQueue` escalation semantics from the readpackets spec - now reachable only under systemic overload.
- Conntrack role contract. `src/conntrack` role operations fuse lookup and TTL refresh in one pass and own entry-pair liveness; timestamp refresh is an atomic write under the shared bucket lock; storage remains the fixed-size hashed table with per-bucket locks (prior decision preserved). Role lookups return narrow role-specific snapshots without `process_name`; the full-entry snapshot remains only for TCP relay connection setup.
- Touch removal. `src/path/return.c` and `src/dns/plan.c` use fused role gets and issue no separate touches. `src/relay/tcp.c` removes per-recv-completion touches and keeps the 20s periodic refresh as a conntrack-owned pair-refresh operation (3x margin within the 60s TTL). `src/relay/udp.c` removes all conntrack touch calls.
- UDP tracking keys. Outbound proxied UDP entries move to full-tuple keys (client, server) so per-destination policy decisions are preserved; return entries stay keyed (server_ip, client_port), one per server. Tracked outbound UDP datagrams take a fused get-and-refresh fast path in `src/path/proxy.c`; process lookup, policy match, and tracking run only for tuples without a live entry.
- Planner identity scoping. Untracked non-SYN TCP in `src/path/proxy.c` keeps the fail-closed drop but consults only the cached flow index for the self-pass guard - no synchronous owner-table refresh, no sleep. Retry-with-refresh remains only on the SYN/new-flow path.
- UDP forward frame. The executor-to-relay frame in `src/flow/executor.c` and `src/relay/udp.c` becomes src_ip(4) src_port(2) dst_ip(4) dst_port(2) payload. The relay wraps each datagram toward its framed destination and routes each response using the unwrapped SOCKS source address, with the conntrack entry retained as the validity gate.
- UDP relay loop. Per-datagram `check_ctrl_alive` is removed; control-socket liveness moves to the periodic cleanup pass (ctrl-dead sessions already survive today, so behavior is preserved). `last_activity` becomes an atomic store under the shared session lock; the LRU list is replaced by a min-timestamp scan at eviction and cleanup over the bounded session table.
- Counters. Existing ndisapi, conntrack, relay, and overload counters remain available; no counter is removed.

## Test strategy
- Extend the flow tests so a multi-packet worker drain executes pass, rewrite/send, drop, UDP relay forward, and DNS forward together with at most one sender enqueue per target per executor flush, and per-flow ordering preserved through the worker queue.
- Add pool/queue tests for the derived-capacity invariant (pool covers reader in-flight plus downstream queue capacity), event-driven wakeup of blocked acquire/enqueue, and unchanged exhaustion escalation counters.
- Add conntrack role tests covering fused get-and-refresh for direct TCP, TCP proxy outbound, TCP proxy return, UDP proxy outbound, UDP proxy return, and TCP DNS return; pair liveness for one-way UDP flows; narrow snapshots on packet paths; full-tuple UDP outbound keys with per-server return entries.
- Add planner tests proving untracked non-SYN TCP drops without triggering an owner-table refresh, while the SYN path still resolves identity with retry.
- Add UDP framing tests: frames carry explicit destination; two destinations from one client port are wrapped and restored independently in both directions.
- Add UDP relay tests: no per-datagram liveness probe (via socket stubs), eviction selects the oldest session by timestamp, idle expiry unchanged.
- Keep `tests/flow_t1_test.c`, `tests/ndisapi_readers_test.c`, `tests/lifecycle_shutdown_test.c`, and `tests/log_levels_test.c` green; each slice documents its standalone build/test commands or adds the missing CTest target, per the readpackets spec convention.

## Out of scope
- Process lookup refresh and miss-latency redesign (still deferred to its own research/spec; this spec only removes call sites that cannot affect disposition).
- Replacing the UDP relay select loop with IOCP.
- Dynamic adapter hot-plug (readpackets phase 2).
- IPv6 support.
- Config schema or CLI changes.
- Replacing WinpkFilter/NDISAPI or the SOCKS5 architecture.
- Changing proxy/direct policy semantics beyond making UDP decisions per-destination-correct.
- DNS NAT lock granularity and per-query cleanup sweep (observed, rated minor at DNS rates; revisit if measured).

## Further notes
User stories come from the 2026-06-11 structure review conversation (five accepted candidates); no `questions.md` exists for this topic. This spec follows up on `../2026-06-11-readpackets-replacement/spec.md` and `../2026-06-11-strong-data-flow-architecture/spec.md`, both done; it changes runtime ownership and contracts at their seam without reopening their behavioral baselines.

Decision-conflict resolution: the strong-data-flow spec deferred process-lookup redesign. This spec honors that deferral - the untracked non-SYN change avoids invoking the lookup where identity cannot change the outcome, and does not alter refresh or miss-latency behavior. The worker-head-of-line evidence from the review is recorded here as motivation to open that deferred research if new-flow latency is measured as a bottleneck.

Two items exceed the review's five candidates and were folded in deliberately: the reader drain-per-wake decision (same files and burst-latency story as the capacity work) and the UDP destination framing (a latent multi-destination mis-routing that the UDP role-key change would otherwise harden into a wrong-by-construction fast path). Both are flagged so slicing can sequence them consciously.

The UDP frame header change is an internal contract between `src/flow/executor.c` and `src/relay/udp.c` only; no on-the-wire or operator-visible format changes.
