# Conntrack Fused Role Operations

**Status**: done
**Serial**: T5
**Spec**: ../spec.md
**Depends on**: T0 (none - independent of the ndisapi chain; T7 builds on it)

## Goal
Conntrack role operations fuse lookup with TTL refresh and own entry-pair liveness, so planners and relays stop choreographing touch calls and stop copying process names on per-packet paths.

## Acceptance
- [x] Role operations fuse lookup and TTL refresh in one bucket pass for direct TCP, TCP proxy outbound, TCP proxy return, UDP proxy outbound, UDP proxy return, and TCP DNS return; refresh is an atomic timestamp write under the shared bucket lock; storage stays the fixed-size hashed table with per-bucket locks.
- [x] Entry-pair liveness is owned by conntrack: a flow whose traffic arrives through only one role's operation keeps both paired entries alive (one-way UDP flow test).
- [x] Role lookups return narrow role-specific snapshots without `process_name`; the full-entry snapshot remains only for TCP relay connection setup.
- [x] `src/path/return.c` and `src/dns/plan.c` issue no separate touch calls.
- [x] `src/relay/tcp.c` issues no per-recv-completion touches; its 20s periodic refresh uses a conntrack-owned pair-refresh operation.
- [x] `src/relay/udp.c` issues no conntrack touch calls.
- [x] Existing return-path and flow behaviors stay green, including TCP proxy return, UDP proxy return, and TCP DNS return.

## Notes
Traceability: Story 2; technical decisions "Conntrack role contract" and "Touch removal".

Today a proxied TCP return packet costs one get (full-entry memcpy including `process_name[256]`) plus two exclusive-lock touches on two buckets, and the TCP relay's per-recv touches are redundant against its own 20s refresh within the 60s TTL. Pitfall: outbound tracked TCP today refreshes nothing - entry A liveness currently depends on the return path's touch - so the fused outbound op must take over that responsibility before the return-path touches disappear.

Implementation: `conntrack_role_snapshot_t` (14 bytes, no process_name) plus fused ops `conntrack_role_tcp_outbound` (covers direct and proxied entry A; refreshes self), `conntrack_role_tcp_return` (refreshes B plus paired A), `conntrack_role_udp_outbound` / `conntrack_role_udp_return` (each refreshes both UDP pair entries - one-way flows stay alive), `conntrack_role_tcp_dns_return`, and `conntrack_role_refresh_tcp_pair` for the relay's 20s pass. Refresh is `InterlockedExchange64` on the timestamp under shared bucket locks; twin keys are extracted in the same lock pass as the lookup. The five role-touch APIs were deleted from `inc/conntrack/conntrack.h`; callers migrated: `src/path/return.c`, `src/dns/plan.c`, `src/path/proxy.c` (tracked non-SYN) use fused ops with no touch calls; `src/relay/tcp.c` lost its per-recv-completion touches (the 20s pair refresh remains the liveness owner, 3x margin under the 60s TTL); `src/relay/udp.c` lost all four touch calls. TCP entry A liveness no longer depends on return traffic (the outbound op refreshes it), and TCP entry B intentionally expires if both return traffic and the relay are gone (fail-closed).

New dedicated suite `tests/conntrack_roles_test.c` runs against the real `src/conntrack/conntrack.c` with a tick hook, asserting fused refresh timestamps for every role, pair liveness for one-way UDP, relay pair refresh, full-entry lookup retained for relay setup, and snapshot narrowness (`sizeof <= 16`). Flow tests now assert role-op counts instead of touch counts. Static check: zero `conntrack_touch_*role*` references remain under `src/`.

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -DWINTPROXY_TEST_HOOKS -Itests/include -Iinc -Ilib tests/conntrack_roles_test.c src/conntrack/conntrack.c -o build-tests/conntrack_roles_test && ./build-tests/conntrack_roles_test
```

plus the T1 command set (flow, readers, log levels, lifecycle, `cmake --build build-mingw -- -j4`) and `grep -rn 'conntrack_touch_tcp_proxy|conntrack_touch_udp_proxy|conntrack_touch_direct_tcp' src/` returning nothing.
