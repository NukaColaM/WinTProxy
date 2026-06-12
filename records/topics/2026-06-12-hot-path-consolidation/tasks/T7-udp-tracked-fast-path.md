# UDP Tracked Fast Path

**Status**: done
**Serial**: T7
**Spec**: ../spec.md
**Depends on**: T5 (the fused get-and-refresh role operation is the fast-path primitive) and T6 (without explicit-destination framing, a tuple-keyed fast path would harden the destination race into wrong-by-construction routing)

## Goal
Established proxied UDP flows skip per-datagram process lookup, policy matching, and conntrack upserts while policy stays correct per destination.

## Acceptance
- [x] Outbound proxied UDP entries are keyed by the full tuple (client ip/port, server ip/port); return entries stay keyed (server_ip, client_port), one per server.
- [x] An outbound UDP datagram whose tuple has a live entry takes the fused get-and-refresh fast path in `src/path/proxy.c`: no process lookup, no policy match, no upsert.
- [x] The first datagram of a tuple (or after TTL expiry) still runs process lookup, policy match, and tracking, preserving fail-closed conntrack-unavailable behavior.
- [x] Per-destination policy is preserved: with a rule set that proxies one destination and directs another, datagrams from one client port to both destinations each follow their own decision (test).
- [x] The UDP relay validity gate works against the new outbound keys.
- [x] UDP proxy return behavior is unchanged, including restoration per actual responding server.

## Notes
Traceability: Stories 2 and 5; technical decision "UDP tracking keys".

Today every outbound proxied UDP datagram re-runs proc lookup, policy, and a double exclusive-lock upsert (`path_plan_policy` -> `conntrack_track_udp_proxy`); that re-tracking is also what the relay's destination recovery depended on, which T6 removes. Pitfall: multiple live tuples can share one client port - the relay session is still keyed by client, so session reuse across destinations must keep working.

Implementation: `conntrack_track_udp_proxy` keys the outbound entry by the full tuple (client ip/port, server ip/port) with rollback by tuple; return entries stay (server_ip, client_port), one per server. `conntrack_get_udp_proxy_outbound` and `conntrack_role_udp_outbound` take the server endpoint; the UDP return twin refresh now targets the full-tuple outbound entry. `path_plan_policy` tries the fused `conntrack_role_udp_outbound` before any identity work and forwards on a hit ("UDP PROXY tracked forward"); first datagrams (or post-TTL) still run identity, policy, and tracking with fail-closed conntrack-unavailable behavior. The relay gate in `handle_client_datagram` validates the framed tuple.

Verified by `tests/flow_t1_test.c` `test_udp_tracked_fast_path_skips_identity_and_policy` (proc-lookup and track counters stay at 1 across a second datagram; role op hit) and `test_udp_policy_stays_per_destination` (one client port: server1 proxied by rule, server2 direct by default - each tuple keeps its own decision); `tests/conntrack_roles_test.c` (full-tuple keys, per-tuple refresh isolation, one-way pair liveness, untracked-tuple miss); `tests/udp_framing_test.c` (per-tuple relay gate: tracked tuples wrap to their framed destination, an untracked destination on a tracked client port drops with counters).

Verified with the T1 + T5 + T6 command sets; all six suites and `cmake --build build-mingw -- -j4` pass.
