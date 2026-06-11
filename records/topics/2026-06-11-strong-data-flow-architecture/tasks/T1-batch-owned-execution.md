# Batch-Owned Execution

**Status**: done
**Serial**: T1
**Spec**: ../spec.md
**Depends on**: T0 (none - this task stands alone)

## Goal
Packets from one NDIS read batch are executed through one owner that groups driver sends by target and preserves existing pass, drop, and rewrite behavior.

## Acceptance
- [x] A read batch with multiple pass/rewrite packets targeting MSTCP performs at most one MSTCP driver send for that executor flush.
- [x] A read batch with multiple pass/rewrite packets targeting adapters performs at most one adapter driver send for that executor flush.
- [x] A mixed read batch containing pass, rewrite/send, drop, UDP relay forward, and DNS forward actions preserves the same externally visible outcomes as the current per-packet execution path.
- [x] Drop, sent, send-failure, and UDP-forward counters remain correct when actions are executed from a batch.
- [x] No direct `SendPacketsToMstcpUnsorted` or `SendPacketsToAdaptersUnsorted` calls remain in the NDIS worker path outside the execution-owned send path.
- [x] Existing flow tests still cover pass, drop, rewrite/send, UDP relay forward, DNS forward, TCP return, and UDP return behavior through the public packet path.

## Notes
Traceability: Stories 1 and 5; technical decisions for execution-owned driver sends, send-target grouping, counters, and NDIS batch send APIs; test strategy for one driver send per target per executor flush.

This task proves the main hot-path improvement without changing packet policy. Socket-forward actions may remain non-driver sends, but they must be explicit executor-owned outcomes rather than hidden worker routing.

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/flow_t1_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/flow_t1_test && ./build-tests/flow_t1_test
```
