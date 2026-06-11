# Dedicated Sender Threads

**Status**: done
**Serial**: T5
**Spec**: ../spec.md
**Depends on**: T4 (sender ownership needs asynchronous flow workers and packet-block ownership so workers can hand off send work safely)

## Goal
Flow workers enqueue driver-send work to dedicated sender threads that batch adapter-specific sends and release packet blocks after send completion.

## Acceptance
- [x] Flow workers no longer call NDISAPI send helpers directly for pass, rewrite/send, or synthetic DNS response actions.
- [x] Dedicated sender ownership exists for adapter-target and MSTCP-target work, with queues that preserve packet-block lifetime until send completion.
- [x] Sender threads batch work by adapter handle and target direction using `ETH_M_REQUEST`.
- [x] `SendPacketsToAdapter` and `SendPacketsToMstcp` partial/failure outcomes update counters and logs and release or account for packet blocks correctly.
- [x] Synthetic DNS response actions enqueue to the MSTCP sender path with the correct adapter handle.
- [x] Shutdown wakes sender threads and drains accepted send work for a bounded interval before stopping.
- [x] Tests verify worker-to-sender handoff, batching by adapter/target, send failure accounting, block release after send, and no direct worker driver sends.

## Notes
Traceability: Stories 3, 4, 5, and 6; technical decisions for dedicated sender threads, adapter-specific batching, sender partial/failure counters, DNS response injection, and bounded drain.

This slice finishes the core multi-stage ownership model: readers read, workers plan and prepare outcomes, senders own driver I/O.

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -DWINTPROXY_TEST_HOOKS -Itests/include -Iinc -Ilib tests/ndisapi_readers_test.c src/ndisapi/adapter.c src/packet/context.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/ndisapi_readers_test && ./build-tests/ndisapi_readers_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/flow_t1_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/flow_t1_test && ./build-tests/flow_t1_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/log_levels_test.c tests/support/stubs.c src/flow/action.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/log_levels_test && ./build-tests/log_levels_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/lifecycle_shutdown_test.c src/app/lifecycle.c -o build-tests/lifecycle_shutdown_test && ./build-tests/lifecycle_shutdown_test
if rg -n "ndisapi_send_batch_to_(adapter|mstcp)" src/flow; then exit 1; fi
cmake --build build-mingw -- -j2
```
