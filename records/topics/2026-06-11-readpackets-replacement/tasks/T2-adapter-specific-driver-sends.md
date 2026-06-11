# Adapter-Specific Driver Sends

**Status**: done
**Serial**: T2
**Spec**: ../spec.md
**Depends on**: T1 (adapter-specific reads provide reliable adapter identity for adapter-specific sends and remove the old ingress fallback first)

## Goal
Packets are returned to NDISAPI through adapter-specific `SendPacketsToAdapter` and `SendPacketsToMstcp` requests instead of unsorted send APIs.

## Acceptance
- [x] Production driver-send helpers build `ETH_M_REQUEST` batches grouped by adapter handle and target direction.
- [x] Pass and rewrite/send actions send packets through adapter-specific `SendPacketsToAdapter` or `SendPacketsToMstcp`.
- [x] Synthetic DNS responses enter the adapter-specific MSTCP send path with the intended adapter handle.
- [x] Partial sends and send failures update counters and logs with the adapter handle and target direction.
- [x] Existing flow tests still pass for pass, drop, rewrite/send, UDP relay forward, DNS forward, TCP return, UDP return, and DNS response injection behavior.
- [x] A static check or targeted test fails if production `src` code references `SendPacketsToAdaptersUnsorted` or `SendPacketsToMstcpUnsorted`.

## Notes
Traceability: Stories 1, 4, and 6; technical decisions for no unsorted send APIs, adapter-specific send APIs, compatible packet planning, DNS response injection, and sender failure counters.

This task may still execute sends synchronously from the current execution path. Dedicated sender threads are a later slice, but the production unsorted send APIs should be gone here.

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -DWINTPROXY_TEST_HOOKS -Itests/include -Iinc -Ilib tests/ndisapi_readers_test.c src/ndisapi/adapter.c src/packet/context.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/ndisapi_readers_test && ./build-tests/ndisapi_readers_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/flow_t1_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/flow_t1_test && ./build-tests/flow_t1_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/log_levels_test.c tests/support/stubs.c src/flow/action.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/log_levels_test && ./build-tests/log_levels_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/lifecycle_shutdown_test.c src/app/lifecycle.c -o build-tests/lifecycle_shutdown_test && ./build-tests/lifecycle_shutdown_test
if rg -n "\b(SendPacketsToAdaptersUnsorted|SendPacketsToMstcpUnsorted)\b" src; then exit 1; fi
cmake --build build-mingw -- -j2
```
