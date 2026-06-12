# UDP Relay Datagram Path Slimming

**Status**: done
**Serial**: T9
**Spec**: ../spec.md
**Depends on**: T6 and T7 (the datagram handlers and validity gate they reshape must settle before this slice strips locking and liveness from those same functions)

## Goal
The UDP relay's per-datagram path runs without liveness probes or exclusive locks, keeping the single relay thread viable at higher session counts.

## Acceptance
- [x] No per-datagram `check_ctrl_alive`: control-socket liveness is evaluated by the periodic cleanup pass, and ctrl-dead sessions still survive on their relay socket exactly as today.
- [x] `last_activity` updates are atomic stores under the shared session lock; the datagram path acquires no exclusive session lock.
- [x] The LRU active list is removed; session eviction when the table is full and idle cleanup both select by timestamp scan over the bounded session table.
- [x] Idle expiry semantics are unchanged (`WTP_UDP_SESSION_TTL_SEC`), and eviction still prefers the oldest session (test).
- [x] A stub-level test shows zero liveness syscalls (ioctl/peek) on the per-datagram path while datagrams still forward and restore correctly.

## Notes
Traceability: Story 6; technical decision "UDP relay loop".

Today every outbound datagram pays two `ioctlsocket` calls plus a `recv(MSG_PEEK)` in `check_ctrl_alive` and an exclusive lock in `update_session_activity`; the liveness check's only effect is nulling a field on sessions that survive anyway. Pitfall: with the LRU list gone, `alloc_session` and `cleanup_idle_sessions` must agree on the timestamp source so a fresh session is never evicted while stale ones remain (the scan is at most `WTP_UDP_SESSION_MAX` = 256 entries).

Implementation: `ensure_session` is now a shared-lock find with no socket probing; `check_ctrl_alive` is called only from `cleanup_idle_sessions`, which owns both idle expiry and control-socket liveness in one bounded array scan (ctrl-dead sessions keep their relay socket; only the dead handle is released). `update_session_activity` takes the shared lock and stores `last_activity` via `InterlockedExchange64`. The LRU active list (active_prev/active_next/active_head/active_tail) was deleted from `inc/relay/udp.h`; eviction in `alloc_session` and the fd-set snapshot both scan the bounded session table, and eviction selects the oldest timestamp. Test seams `udp_relay_test_alloc_oldest` / `udp_relay_test_cleanup_idle` are hooks-gated.

Verified by `tests/udp_framing_test.c`: `test_datagram_path_avoids_probe_and_exclusive_locks` (zero ioctl/peek probes and zero exclusive lock acquisitions on both datagram directions, with forwarding and response routing still observed over real sockets), `test_eviction_prefers_oldest_session` (table-full eviction picks the oldest timestamp, not list position), and `test_periodic_cleanup_owns_idle_and_ctrl_liveness` (idle session closed at the 300s TTL, fresh sessions kept, ctrl probe happens in the periodic pass). Harness gained `g_test_windows_srw_exclusive_count` and `g_test_winsock_ioctl_count` hooks.

Verified with the T6 command set plus the full suite; `cmake --build build-mingw -- -j4` passes and `check_ctrl_alive` has no datagram-path callers (static check).
