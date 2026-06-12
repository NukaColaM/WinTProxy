# Grouped Reader Dispatch

**Status**: done
**Serial**: T2
**Spec**: ../spec.md
**Depends on**: T1 (the worker drain defines the consumer contract the grouped enqueue feeds; reshaping the queue contract once avoids churning T1's drain semantics)

## Goal
Adapter readers hand each read batch to flow workers in per-worker groups and drain the adapter queue per wake, so dispatch costs amortize per batch and burst backlogs are not stranded behind the event timeout.

## Acceptance
- [x] Readers group accepted blocks by target flow worker within one read batch and enqueue each group with one queue lock acquisition and one wake per worker per read batch.
- [x] The flow-worker enqueue contract in `inc/ndisapi/adapter.h` accepts multiple blocks; bounded-wait then drop-with-counters overload behavior is preserved for a full queue.
- [x] Flow affinity is unchanged: same hash, same worker mapping, both directions of one flow on one adapter still map together.
- [x] Readers repeat `ReadPackets` while it returns a full batch before re-waiting on the packet event, bounded by pool availability, so a queued backlog larger than one batch drains without waiting for the next packet arrival or the 100ms timeout.
- [x] Tests verify per-batch lock/wake counts via stubs, backlog drain across consecutive reads, same-flow ordering through grouped dispatch, and existing reader behaviors.

## Notes
Traceability: Stories 1 and 3; technical decisions "Batch unit" (reader grouping) and "Reader drain".

Grouping happens in `ndisapi_reader_proc` after a successful read; worker index is already computed per block. Pitfall: a partially full group whose worker queue fills must drop only that group's overflow, not the whole read batch; released blocks must return to the pool before the next acquire loop.

Implementation: `ndisapi_flow_worker_dispatch_batch` (declared in `inc/ndisapi/adapter.h`) computes worker indexes once per chunk, gathers per-worker groups, and enqueues each group via a single-lock `ndisapi_flow_worker_enqueue_group` that wakes the worker once; overflow keeps per-block `enqueue_timeouts`/overload counters and releases blocks after a single grouped warn log. `ndisapi_flow_worker_enqueue` is now a one-block wrapper, preserving the T-prior overload test contract. The reader loop drains with an inner for(;;): full batches keep reading, a partial batch or pool exhaustion returns to the event wait. Verified by `test_reader_drains_backlog_with_grouped_dispatch` (2 reads on 1 wait, 1 wake per read batch, 257 packets queued) and `test_flow_worker_dispatch_batch_groups_and_drops` (partial enqueue into 2 free slots, 2 overflow drops with counters and releases, single wake). A wait-count hook was added to `tests/include/windows.h` under `WINTPROXY_TEST_HOOKS`.

Verified with the same commands as T1 (readers test exercises the new dispatch; full suite plus `cmake --build build-mingw -- -j4` pass).
