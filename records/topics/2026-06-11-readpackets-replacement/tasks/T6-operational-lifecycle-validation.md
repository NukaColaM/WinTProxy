# Operational Lifecycle And Validation

**Status**: done
**Serial**: T6
**Spec**: ../spec.md
**Depends on**: T5 (the complete reader, worker, and sender thread graph must exist before final lifecycle and smoke validation are meaningful)

## Goal
The replacement reports stale adapter state, shuts down predictably, and has an explicit manual Windows smoke checklist for live-driver validation.

## Acceptance
- [x] Phase 1 detects adapter-list changes after start and logs that restart is required without creating or removing live adapter readers.
- [x] Adapter restart-required events increment a visible counter or compatible snapshot field.
- [x] Stop order is implemented as: stop readers, wake adapter events, stop cross-thread producers, drain accepted worker/sender work briefly, stop sender threads, reset adapter modes/events, free packet blocks, close driver and sockets.
- [x] Repeated stop calls are safe and do not double-free packet blocks, events, threads, or driver handles.
- [x] Local lifecycle tests cover blocked reader wakeup, bounded worker/sender drain, adapter event release, adapter mode reset, and repeated stop.
- [x] Final static checks confirm no production references to `ReadPacketsUnsorted`, `SendPacketsToAdaptersUnsorted`, or `SendPacketsToMstcpUnsorted` remain.
- [x] Task verification notes include a manual Windows smoke checklist covering WinpkFilter load, per-adapter reader startup, TCP/UDP/DNS traffic, counter movement, no duplicate traffic under concurrent adapters, adapter-list change restart-required log, and clean stop.

## Notes
Traceability: Stories 5 and 6; technical decisions for restart-required adapter changes, bounded shutdown order, no unsorted production APIs, and manual Windows smoke validation.

Dynamic adapter reader creation and removal remain phase 2. This task only makes phase 1 operationally honest and verifiable.

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -DWINTPROXY_TEST_HOOKS -Itests/include -Iinc -Ilib tests/ndisapi_readers_test.c src/ndisapi/adapter.c src/packet/context.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/ndisapi_readers_test && ./build-tests/ndisapi_readers_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/flow_t1_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/flow_t1_test && ./build-tests/flow_t1_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/log_levels_test.c tests/support/stubs.c src/flow/action.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/log_levels_test && ./build-tests/log_levels_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/lifecycle_shutdown_test.c src/app/lifecycle.c -o build-tests/lifecycle_shutdown_test && ./build-tests/lifecycle_shutdown_test
if rg -n "\b(ReadPacketsUnsorted|SendPacketsToAdaptersUnsorted|SendPacketsToMstcpUnsorted)\b" src; then exit 1; fi
cmake --build build-mingw -- -j2
```

Manual Windows smoke checklist:

- Confirm WinpkFilter is installed, `ndisrd.sys` is loaded, and WinTProxy starts without driver-load errors.
- Start WinTProxy with debug logging and verify the log reports one adapter reader per enumerated adapter, flow workers, and sender threads.
- Generate TCP, UDP, and DNS traffic through at least two active adapters and verify `packets recv`, `sent`, `dropped`, `udp_to_relay`, and relay counters move as expected.
- Confirm traffic is not duplicated while concurrent adapters are active.
- Trigger an adapter-list change after startup and verify the log says restart is required and the `restart_required` debug counter increments.
- Stop WinTProxy and verify adapter modes/events are reset and the process exits cleanly.
