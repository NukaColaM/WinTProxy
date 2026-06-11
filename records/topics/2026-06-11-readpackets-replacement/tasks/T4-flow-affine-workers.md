# Flow-Affine Worker Dispatch

**Status**: done
**Serial**: T4
**Spec**: ../spec.md
**Depends on**: T2 and T3 (workers must process packet blocks with safe lifetime ownership and must not reintroduce unsorted driver sends)

## Goal
Adapter readers dispatch packets to auto-sized bounded flow workers that preserve per-flow ordering while allowing different flows to run in parallel.

## Acceptance
- [x] Flow worker count is auto-sized from logical CPU count and clamped to 2..16.
- [x] Each flow worker queue has a bounded depth of 512 packet items.
- [x] IPv4 TCP/UDP flow affinity uses adapter handle plus normalized protocol and endpoint tuple so both directions of one flow map to the same worker.
- [x] Non-IP, unsupported protocol, and unparseable packets are assigned deterministically by adapter handle and packet direction.
- [x] Adapter readers enqueue accepted packet blocks to flow workers with a short bounded wait, then drop and release the block with counters if the queue remains full.
- [x] Flow workers run `packet_parse`, `traffic_plan_packet`, and execution-equivalent behavior without reordering packets from the same flow.
- [x] Tests verify same-flow ordering, cross-flow parallel dispatch eligibility, adapter-separated keys, queue-full timeout drops, and existing flow behavior preservation.

## Notes
Traceability: Stories 2, 3, 5, and 6; technical decisions for CPU-based auto-sizing, bounded queues, flow affinity, enqueue timeout drops, and compatible packet planning.

This is the main throughput slice. The visible result is that intake no longer serializes packet planning and execution behind each adapter reader, while correctness remains per-flow.

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -DWINTPROXY_TEST_HOOKS -Itests/include -Iinc -Ilib tests/ndisapi_readers_test.c src/ndisapi/adapter.c src/packet/context.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/ndisapi_readers_test && ./build-tests/ndisapi_readers_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/flow_t1_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/flow_t1_test && ./build-tests/flow_t1_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/log_levels_test.c tests/support/stubs.c src/flow/action.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/log_levels_test && ./build-tests/log_levels_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/lifecycle_shutdown_test.c src/app/lifecycle.c -o build-tests/lifecycle_shutdown_test && ./build-tests/lifecycle_shutdown_test
cmake --build build-mingw -- -j2
```
