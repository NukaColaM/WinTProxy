# Packet Block Pool And Overload Handling

**Status**: done
**Serial**: T3
**Spec**: ../spec.md
**Depends on**: T1 (adapter readers need packet blocks before issuing adapter-specific `ReadPackets`, and overload handling flushes a specific adapter queue)

## Goal
Adapter readers use bounded ref-counted packet blocks, and sustained pool exhaustion is visible through adapter-local flushes and counters.

## Acceptance
- [x] `src/ndisapi` owns a bounded shared packet-block pool for caller-owned `INTERMEDIATE_BUFFER` storage and per-packet runtime metadata.
- [x] Packet blocks carry adapter identity, direction, parsed context/action storage as needed, and explicit ref-counted ownership state.
- [x] Adapter readers acquire blocks before `ReadPackets` and do not reuse a block until all accepted downstream ownership releases it.
- [x] If the free pool is exhausted, a reader waits only for a bounded interval before calling `FlushAdapterPacketQueue` for that adapter.
- [x] Pool-exhaustion flushes increment explicit counters, count affected traffic as dropped/overloaded, and log adapter identity.
- [x] Unit or harness tests cover block acquire/release, ref-count transitions, exhausted-pool timeout, adapter queue flush, and counters.

## Notes
Traceability: Stories 3, 5, and 6; technical decisions for bounded packet-block pool, ref-count ownership, adapter-local flush on exhaustion, overload counters, and local contract tests.

This slice gives operators explicit overload behavior before packet processing becomes asynchronous. It should preserve the packet behavior already proven by T1 and T2.

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -DWINTPROXY_TEST_HOOKS -Itests/include -Iinc -Ilib tests/ndisapi_readers_test.c src/ndisapi/adapter.c src/packet/context.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/ndisapi_readers_test && ./build-tests/ndisapi_readers_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/flow_t1_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/flow_t1_test && ./build-tests/flow_t1_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/log_levels_test.c tests/support/stubs.c src/flow/action.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/log_levels_test && ./build-tests/log_levels_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/lifecycle_shutdown_test.c src/app/lifecycle.c -o build-tests/lifecycle_shutdown_test && ./build-tests/lifecycle_shutdown_test
cmake --build build-mingw -- -j2
```
