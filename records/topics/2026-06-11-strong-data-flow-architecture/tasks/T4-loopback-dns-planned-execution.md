# Loopback DNS Planned Execution

**Status**: done
**Serial**: T4
**Spec**: ../spec.md
**Depends on**: T3 (loopback DNS response restoration depends on execution-owned sends, read-only observations, and conntrack/DNS role contracts being narrowed first)

## Goal
Loopback DNS forwarding and response injection follow the same planned execution model as the rest of the packet flow.

## Acceptance
- [x] Loopback UDP DNS query forwarding is represented as an explicit planned/executed outcome, preserving client TXID, source port, original resolver address, and adapter selection.
- [x] Loopback DNS responses are restored and injected through the execution-owned send path rather than direct driver injection from the DNS forwarder.
- [x] Direct calls to `SendPacketsToMstcpUnsorted` or `SendPacketsToAdaptersUnsorted` are absent from the DNS forwarder.
- [x] Loopback DNS forward, NAT, or synthetic response failures fail closed unless a test proves a specific fallback is safe.
- [x] Normal UDP DNS rewrite, TCP DNS redirect/return, DNS-before-policy ordering, and DNS self/loop protection continue to behave as before.
- [x] Tests cover successful loopback DNS forwarding, response restoration, missing NAT state, send failure, normal UDP DNS, and TCP DNS cases.

## Notes
Traceability: Stories 1, 4, and 5; technical decisions for loopback DNS fitting the shared plan/execute model and removing direct driver injection from the DNS forwarder.

This task is last because it should reuse the execution-owned send path and read-only packet observation rather than building another DNS-specific transport path.

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/flow_t1_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/flow_t1_test && ./build-tests/flow_t1_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/log_levels_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/log_levels_test && ./build-tests/log_levels_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/lifecycle_shutdown_test.c tests/support/stubs.c src/app/lifecycle.c -o build-tests/lifecycle_shutdown_test && ./build-tests/lifecycle_shutdown_test
rg -n "SendPacketsTo(Mstcp|Adapters)Unsorted" src/dns inc/dns -g '*.[ch]'
```
