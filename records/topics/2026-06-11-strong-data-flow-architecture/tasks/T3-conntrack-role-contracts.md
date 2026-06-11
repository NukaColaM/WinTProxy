# Conntrack Role Contracts

**Status**: done
**Serial**: T3
**Spec**: ../spec.md
**Depends on**: T2 (role-specific conntrack snapshots should be consumed by planners that already use read-only packet observations)

## Goal
Proxy, direct, return-path, DNS, and relay code use conntrack-owned role operations instead of assembling tuple roles in callers.

## Acceptance
- [x] Direct TCP, TCP proxy outbound, TCP proxy return, UDP proxy outbound, UDP proxy return, and TCP DNS return flows use role-specific conntrack operations or snapshots.
- [x] Packet planners and relays no longer need to know Entry A/Entry B tuple encoding or manually assemble full conntrack keys for proxy return roles.
- [x] Missing or stale conntrack state still fails closed for unsafe proxy, DNS, and return-path traffic.
- [x] Direct TCP flows observed from SYN after startup still pass subsequent non-SYN packets without being treated as preexisting bypass traffic.
- [x] Tests cover role creation, role lookup, role refresh/touch, missing-state drop behavior, and relay consumption for TCP and UDP.
- [x] Conntrack remains a fixed-size hashed table with per-bucket locking unless a test proves the storage shape must change.

## Notes
Traceability: Stories 3 and 5; technical decision to replace caller-assembled conntrack role usage in `src/path`, `src/dns`, and `src/relay` with conntrack-owned role operations and role-specific snapshots.

The goal is to hide role encoding, not to replace conntrack storage. Relay protocol internals should only change where they consume the narrower role contract.

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/flow_t1_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/flow_t1_test && ./build-tests/flow_t1_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib tests/log_levels_test.c tests/support/stubs.c src/flow/action.c src/flow/executor.c src/flow/plan.c src/path/bypass.c src/path/classify.c src/path/proxy.c src/path/return.c src/dns/plan.c src/policy/rules.c -o build-tests/log_levels_test && ./build-tests/log_levels_test
gcc -std=c11 -Wall -Wextra -D_WIN32 -Itests/include -Iinc -Ilib -c src/conntrack/conntrack.c -o build-tests/conntrack.o
rg -n --glob '*.[ch]' -- "conntrack_(add_key_full|add_key|add\\(|get_full_key|get_full\\(|touch_key|remove_key|remove\\()" src/path src/dns src/relay inc/path inc/dns inc/relay
```
