# Worker Batch Execution

**Status**: done
**Serial**: T1
**Spec**: ../spec.md
**Depends on**: T0 (none - this task stands alone)

## Goal
Flow workers drain their queue and execute the drained packets as one action batch, so sender handoff costs amortize per batch instead of repeating per packet.

## Acceptance
- [x] A flow worker wake drains queued blocks (bounded by `NDISAPI_BATCH_SIZE`) in one queue pass, parses and plans each into block-owned storage, and executes the drained set through one `traffic_execute_actions` call.
- [x] Pass and rewrite actions in one drained batch produce at most one sender-queue enqueue (one sender lock acquisition, one wake) per send target per executor flush.
- [x] Packets of the same flow execute in arrival order through the drain.
- [x] Drop, UDP relay forward, and DNS forward remain explicit per-action outcomes inside the batch loop, with counters correct when executed from a batch.
- [x] Existing flow behaviors stay green: pass, drop, rewrite/send, UDP relay forward, normal DNS rewrite, loopback DNS forwarding, TCP DNS, TCP proxy return, UDP proxy return, direct TCP, fail-closed missing-state cases.

## Notes
Traceability: Story 1; technical decisions "Batch unit" (worker drain) and "Executor flush".

This is the riskiest core slice and anchors the topic: it re-establishes the batch as the unit of work that T2-T4 build on. The executor's target-grouped arrays (`src/flow/executor.c`) already accept arrays; the change is the worker loop in `src/ndisapi/adapter.c` draining like the senders already do (`ndisapi_sender_dequeue_many` is prior art). Reader-side dispatch is intentionally untouched here (T2). Pitfall: blocks must be released only after the batch executes, and a parse failure inside a drain must not abort the remaining blocks.

Implementation: block-owned actions are not contiguous, so the executor gained `traffic_execute_action_batch(engine, traffic_action_t *const *, size_t)` in `inc/flow/executor.h`; both batch entry points share one per-action core. `ndisapi_enqueue_send_batch` now enqueues a whole chunk under one sender lock and issues one wake; per-item overflow drops keep their counters and are logged outside the lock. Worker drain uses `ndisapi_flow_worker_dequeue_many` (mirrors the sender dequeue); behavior verified by `test_flow_worker_drains_batch_into_single_sender_enqueue` (one sender wake per drain, one grouped driver send, marker-byte arrival order, pool fully released).

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -DWINTPROXY_TEST_HOOKS -Itests/include -Iinc -Ilib tests/ndisapi_readers_test.c src/ndisapi/adapter.c src/packet/context.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/ndisapi_readers_test && ./build-tests/ndisapi_readers_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/flow_t1_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/flow_t1_test && ./build-tests/flow_t1_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/log_levels_test.c tests/support/stubs.c src/flow/action.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/log_levels_test && ./build-tests/log_levels_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/lifecycle_shutdown_test.c src/app/lifecycle.c -o build-tests/lifecycle_shutdown_test && ./build-tests/lifecycle_shutdown_test
cmake --build build-mingw -- -j4
```
