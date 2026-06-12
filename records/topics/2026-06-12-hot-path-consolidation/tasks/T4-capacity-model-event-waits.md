# Capacity Model And Event Waits

**Status**: done
**Serial**: T4
**Spec**: ../spec.md
**Depends on**: T2 (event waits replace the sleeps inside the reader acquire and enqueue paths that T2 reshapes, and the capacity model must cover grouped-dispatch in-flight demand)

## Goal
Pool and queue sizes derive from one in-flight capacity model and blocked stages wait on events, so bursts shed the newest packets with counters instead of stalling on timer quanta and flushing the adapter queue.

## Acceptance
- [x] Pool capacity is derived at start from reader in-flight batches (adapters x `NDISAPI_BATCH_SIZE` x 2) plus total flow-queue depth plus total sender-queue depth, and the derived sizes are logged at start.
- [x] Driver-side `SetPoolSize` is aligned to the reader in-flight component.
- [x] Pool acquire waits on a free-space event signaled when blocks return to an empty pool; flow-worker enqueue waits on a per-worker space event; no `Sleep(1)` polling remains on these paths.
- [x] Bounded-wait, drop-newest, and `FlushAdapterPacketQueue` escalation semantics and all overload counters (`pool_exhausted`, `adapter_queue_flushes`, `overload_drops`, `enqueue_timeouts`) are preserved.
- [x] Tests verify a blocked acquire wakes promptly on release (not timer-quantum bound), the sizing invariant (pool covers reader in-flight plus downstream queue capacity), and that exhaustion still flushes and counts.

## Notes
Traceability: Story 3; technical decision "Capacity model".

The current pool (adapters x 512) is smaller than one flow worker queue, so the binding constraint today is the pool and the flush cliff is easy to reach; after this slice, pool exhaustion means systemic overload. Pitfall: the free-space event must not lose wakeups when multiple readers block simultaneously; memory cost of the derived pool (roughly 2 KB per block) should be logged so operators can see the footprint.

Implementation: `ndisapi_packet_pool_capacity_for(adapters, workers)` returns reader in-flight (adapters x 256 x 2) + workers x 512 + 2 x 1024; `ndisapi_start` selects the worker count before pool allocation and logs the component breakdown; `SetPoolSize` keeps the reader in-flight value (stub-captured and asserted). The pool gained `free_event` (signaled by release into an empty pool only) and each worker gained `space_event` (signaled when a dequeue frees a full queue); `ndisapi_packet_block_acquire_or_flush` and `ndisapi_flow_worker_dispatch_batch` use the arm/re-check/wait-once pattern, so no `Sleep(1)` polling remains on either path (pinned by a Sleep hook asserting zero sleeps on the exhaustion and overflow paths). Escalation (`FlushAdapterPacketQueue`) and all overload counters are unchanged.

Verified with the same commands as T1 (readers test includes `test_pool_capacity_derived_from_inflight_model` and `test_pool_release_into_empty_pool_signals_free_event`; full suite plus `cmake --build build-mingw -- -j4` pass).
