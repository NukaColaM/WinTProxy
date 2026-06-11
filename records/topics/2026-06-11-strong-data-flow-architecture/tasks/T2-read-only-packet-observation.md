# Read-Only Packet Observation

**Status**: done
**Serial**: T2
**Spec**: ../spec.md
**Depends on**: T1 (batch-owned execution must exist first so mutable frame access has a single execution owner to move into)

## Goal
Packet planning consumes stable observed facts while all packet mutation remains confined to execution.

## Acceptance
- [x] Planning APIs for classify, DNS, bypass, policy, proxy, and return paths consume observed packet facts without requiring mutable header pointers.
- [x] Packet mutation, checksum recalculation, MSS clamping, and payload-dependent frame access happen only through execution-owned mutable frame access.
- [x] Tests verify observed source/destination IPs, ports, protocol, direction, DNS TXID, and payload summary remain stable before and after planning for pass, rewrite/send, DNS, and return-path cases.
- [x] Tests verify executing a rewrite updates the actual packet frame while the planning observation remains unchanged.
- [x] Existing direct, proxy, DNS, self/loop protection, and return-path behavior remains unchanged.

## Notes
Traceability: Stories 2 and 5; technical decision to split packet observation from mutable packet frame access; test strategy for stable observed facts and execution-only mutation.

This task may change packet/context contracts, but it should be delivered through visible packet-flow behavior, not as a standalone type cleanup.

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/flow_t1_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/flow_t1_test && ./build-tests/flow_t1_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/log_levels_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/log_levels_test && ./build-tests/log_levels_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib -c src/packet/context.c -o build-tests/context.o
```
