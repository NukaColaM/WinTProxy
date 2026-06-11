# Strong Data Flow Architecture

**Status**: done

## Problem
The prior full-data-flow refactor established an explicit plan/execute boundary, but the current code still has four strong architectural gaps in the main data flow.

Packet send routing is not fully owned by one execution path: the NDIS worker reads batches, but execution sends packets one at a time, and loopback DNS responses still inject packets from the DNS forwarder. Conntrack role knowledge remains spread across packet planners and relays through caller-assembled tuple conventions. `packet_ctx_t` still mixes observed packet facts with mutable packet handles, so the "no mutation before execute" rule is enforced by convention. Loopback DNS still has its own mini-pipeline for forwarding, NAT state, packet synthesis, and MSTCP injection.

These gaps make the hot path harder to reason about and limit performance improvements under the current single NDIS worker constraint.

## Solution
Finish the strong parts of the data-flow architecture by making execution the single batch-oriented owner of packet sends, making packet observations structurally read-only during planning, hiding conntrack role encoding behind role-specific contracts, and bringing loopback DNS forwarding and response injection into the same plan/execute model as other traffic.

The work should preserve existing operator-visible behavior: config and CLI shape, DNS-before-policy ordering, proxy/direct policy semantics, self/loop protection, fail-closed behavior for unsafe state, and TCP/UDP return-path behavior.

## User stories
1. As a maintainer, I want all packet sends and synthetic packet injection to go through one execution owner, so that routing, counters, batching, and drops are auditable in one place.
2. As a maintainer, I want packet planning to consume immutable observed facts, so that planners cannot accidentally mutate packets or depend on stale mutable header state.
3. As a maintainer, I want conntrack role operations to hide tuple encoding, so that proxy, direct, return-path, DNS, and relay code do not duplicate Entry A/B key knowledge.
4. As an operator, I want loopback DNS to behave like the normal planned data flow, so that DNS forwarding remains correct without a separate packet injection path.
5. As an operator, I want the refactor to preserve current traffic behavior and safety defaults, so that architectural cleanup does not change routing policy.

## Technical decisions
- Modify `src/ndisapi`, `src/flow`, and `inc/flow` so the NDIS worker hands planned work from each read batch to execution. Execution groups pass/rewrite driver sends by target and flushes them through NDIS batch send APIs, while drops and socket-forward actions remain explicit action outcomes.
- Keep the current plan/execute concept, but deepen the execution boundary so `SendPacketsToMstcpUnsorted`, `SendPacketsToAdaptersUnsorted`, and synthetic packet injection are not spread across `src/ndisapi/adapter.c`, `src/flow/executor.c`, and `src/dns/hijack.c`.
- Split packet observation from mutable packet frame access in `src/packet` and `inc/packet`. Planning APIs should expose stable observed facts; execution APIs should own mutable frame handles, header writes, checksum recalculation, and payload-dependent sends.
- Replace caller-assembled conntrack role usage in `src/path`, `src/dns`, and `src/relay` with conntrack-owned role operations and role-specific snapshots. The storage implementation may remain a fixed-size hashed table with per-bucket locks.
- Keep relay protocol internals in `src/relay/tcp.c`, `src/relay/udp.c`, and `src/relay/socks5.c` unless a narrow change is required to consume the new conntrack role contract.
- Rework loopback DNS handling so DNS query forwarding, TXID/NAT state, response restoration, synthetic response construction, and send routing fit the shared plan/execute model. DNS NAT state may remain inside `src/dns`, but direct driver injection from the DNS forwarder should be removed.
- Loopback DNS forward, NAT, or synthetic response failures must fail closed unless a task explicitly proves the fallback is safe. Passing the original DNS query as a fallback is not preserved behavior for this spec.
- Preserve config schema, CLI shape, DNS-before-policy ordering, proxy/direct decisions, self/loop protection, startup quarantine behavior, and TCP/UDP return-path behavior.
- Do not include the process lookup latency concern in this spec. It was rated worth exploring, not strong, and should be handled by a separate research/spec if it becomes a measured bottleneck.

## Test strategy
- Extend the existing flow tests so public packet planning/execution paths cover pass, drop, rewrite/send, UDP relay forward, normal DNS rewrite, loopback DNS forwarding, TCP DNS, TCP proxy return, and UDP proxy return.
- Verify that observed packet facts stay stable through planning and that all packet mutation, checksum recalculation, send routing, and synthetic packet injection happen only in execution.
- Verify that conntrack role operations cover direct TCP, TCP proxy outbound, TCP proxy return, UDP proxy outbound, UDP proxy return, and TCP DNS return without requiring tests to assemble raw tuple roles.
- Verify that loopback DNS query forwarding and response restoration preserve client TXID, source port, original resolver address, adapter selection, and fail-closed behavior when NAT or send state is missing.
- Verify that a read batch with multiple pass/rewrite packets performs at most one driver send per target per executor flush, excluding drops and socket-forward actions.
- Verify that no direct `SendPacketsToMstcpUnsorted` or `SendPacketsToAdaptersUnsorted` calls remain outside the execution-owned path.
- Run the existing build and test flow after slicing adds concrete tasks. If the repository still lacks a CTest target, the slice should either add one or document the exact standalone test commands it verifies.

## Out of scope
- Config schema changes.
- CLI changes.
- IPv6 support.
- Replacing WinpkFilter/NDISAPI.
- Replacing the SOCKS5 proxy architecture.
- Changing proxy/direct policy semantics.
- Broad relay protocol rewrites beyond consuming the narrowed conntrack and execution contracts.
- Process lookup refresh and miss-latency redesign.

## Further notes
This spec follows up on `../2026-05-31-full-data-flow-refactor/spec.md` and its research record, which identified the same architectural direction. The prior task set is already marked done, so this spec represents the remaining strong friction found by the 2026-06-11 structure review rather than a continuation of those task records.

The deletion test favors deepening existing modules over adding a new top-level subsystem: deleting the current executor, conntrack role helpers, or packet context would spread complexity, but each needs a narrower contract so neighboring modules stop carrying hidden state knowledge.
