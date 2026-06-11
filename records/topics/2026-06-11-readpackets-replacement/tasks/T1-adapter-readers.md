# Adapter ReadPackets Readers

**Status**: done
**Serial**: T1
**Spec**: ../spec.md
**Depends on**: T0 (none - this task stands alone)

## Goal
WinTProxy reads packets through one adapter-specific `ReadPackets` reader per enumerated adapter, with no production `ReadPacketsUnsorted` ingress path.

## Acceptance
- [x] Each enumerated adapter has its own packet event and reader thread/context.
- [x] Each reader initializes an `ETH_M_REQUEST` with that adapter handle and caller-owned `INTERMEDIATE_BUFFER` storage before calling `ReadPackets`.
- [x] The shared `packet_event`, unsorted worker-slice allocation, and `ReadPacketsUnsorted` worker loop are removed from production ingress.
- [x] Packets read from adapter-specific readers still pass through existing `packet_parse`, `traffic_plan_packet`, and execution behavior.
- [x] Receive/drop/send counters continue to move correctly for pass, drop, and rewrite/send packet outcomes covered by existing local tests.
- [x] A static check or targeted test fails if production `src` code references `ReadPacketsUnsorted`.

## Notes
Traceability: Stories 1 and 6; technical decisions for adapter-reader contexts, all-adapter interception, no unsorted fallback, and local build/static verification.

This first slice proves the driver intake change without introducing asynchronous flow workers yet. It may keep the current execution boundary until later tasks, but ingress must not fall back to `ReadPacketsUnsorted`.

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -DWINTPROXY_TEST_HOOKS -Itests/include -Iinc -Ilib tests/ndisapi_readers_test.c src/ndisapi/adapter.c src/packet/context.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/ndisapi_readers_test && ./build-tests/ndisapi_readers_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/flow_t1_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/flow_t1_test && ./build-tests/flow_t1_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/log_levels_test.c tests/support/stubs.c src/flow/action.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/log_levels_test && ./build-tests/log_levels_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/lifecycle_shutdown_test.c src/app/lifecycle.c -o build-tests/lifecycle_shutdown_test && ./build-tests/lifecycle_shutdown_test
if rg -n "\bReadPacketsUnsorted\b" src; then exit 1; fi
cmake --build build-mingw -- -j2
```
