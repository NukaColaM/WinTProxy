# Untracked Non-SYN Identity Scoping

**Status**: done
**Serial**: T8
**Spec**: ../spec.md
**Depends on**: T0 (none - confined to the planner's untracked non-SYN branch)

## Goal
A dead flow's retransmits can no longer head-of-line block a flow worker: untracked non-SYN TCP drops fail-closed without synchronous owner-table work.

## Acceptance
- [x] The untracked non-SYN TCP branch in `src/path/proxy.c` consults only the cached flow index for the self-pass guard: no synchronous owner-table refresh, no sleep on this path.
- [x] Self traffic that hits the branch with a cache hit still passes.
- [x] Non-self untracked non-SYN TCP still drops fail-closed with counters and a drop-context label.
- [x] The SYN/new-flow path keeps retry-with-refresh identity resolution and unchanged policy behavior.
- [x] A test proves a burst of untracked non-SYN packets triggers zero synchronous refreshes (stub counter) while SYN-path lookups still resolve.

## Notes
Traceability: Story 4; technical decision "Planner identity scoping".

Today `plan_tcp_non_syn_untracked` calls `proc_lookup_tcp_retry`, whose miss path runs a full `GetExtendedTcpTable`/`GetExtendedUdpTable` rebuild plus `Sleep(1)` on the flow worker, even though both policy outcomes there are drops. Boundary: the recorded deferral of process-lookup refresh/miss-latency redesign stays intact - this slice only stops invoking the expensive path where identity cannot change the disposition.

Implementation: `plan_tcp_non_syn_untracked` now uses the cache-only `proc_lookup_tcp` for the self-pass guard and drops fail-closed with the single context label "TCP non-SYN untracked"; the policy match was removed because both of its outcomes were drops (it only selected the label). The cache-only lookup's miss path signals the background refresher asynchronously - no synchronous `GetExtendedTcpTable` rebuild and no `Sleep` run on a flow worker. The SYN/new-flow path keeps `proc_lookup_tcp_retry`, honoring the recorded deferral of process-lookup redesign.

Verified by `tests/flow_t1_test.c` `test_untracked_non_syn_drops_without_sync_refresh`: a 5-packet untracked non-SYN burst drops with zero retry calls and five cache-only lookups (was five retries before), a self cache hit still passes, and the SYN path still retries identity. Stubs gained controllable pid/self values plus lookup counters.

Verified with the full suite command set; all six suites and `cmake --build build-mingw -- -j4` pass.
