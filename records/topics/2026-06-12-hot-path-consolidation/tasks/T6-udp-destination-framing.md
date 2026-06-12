# UDP Destination Framing

**Status**: done
**Serial**: T6
**Spec**: ../spec.md
**Depends on**: T0 (none - the executor-to-relay frame is independent of the ndisapi and conntrack chains)

## Goal
UDP relay frames carry each datagram's destination and responses are attributed to their actual source server, so one client port talking to several servers is proxied correctly in both directions.

## Acceptance
- [x] The executor-to-relay frame is src_ip(4) src_port(2) dst_ip(4) dst_port(2) payload, produced in `src/flow/executor.c` and parsed in `src/relay/udp.c`.
- [x] The relay wraps each outbound datagram toward its framed destination; no destination is recovered from conntrack on the wrap path.
- [x] Response routing uses the unwrapped SOCKS source address, so the return-path rewrite restores the fields of the server that actually responded.
- [x] The conntrack entry remains the validity gate for client datagrams (untracked client ports are still dropped with counters).
- [x] A test drives two destinations from one client port and verifies each direction independently: wraps carry the right destination, and each server's response is restored with that server's original address and port.
- [x] The frame change is internal to executor and relay; no config, CLI, or on-the-wire format changes.

## Notes
Traceability: Story 5; technical decision "UDP forward frame".

This fixes a latent race found while structuring the spec: today the relay reads the destination from the latest conntrack upsert, so interleaved sends from one port to two servers can be wrapped toward, and responses attributed to, the wrong server. T7's tuple-keyed fast path must not land before this does, or the race hardens into wrong-by-construction routing.

Implementation: `execute_udp_forward` now emits src_ip(4) src_port(2) dst_ip(4) dst_port(2) payload (IPs network order, ports big-endian, matching the prior src convention); `handle_client_datagram` parses the 12-byte header, keeps `conntrack_get_udp_proxy_outbound` purely as the validity gate, and wraps toward the framed destination; `handle_proxy_datagram` routes each response to the unwrapped SOCKS source address and no longer consults conntrack at all. Test seams `udp_relay_test_handle_client_datagram` / `udp_relay_test_handle_proxy_datagram` are exported under `WINTPROXY_TEST_HOOKS` in `inc/relay/udp.h`.

Verified by `tests/flow_t1_test.c` `test_udp_forward_frame_carries_destination` (executor frame received over a real loopback socket and byte-checked) and the new `tests/udp_framing_test.c`, which runs the real relay handlers, real SOCKS5 wrap/unwrap, and real conntrack over loopback sockets: a datagram framed for a second destination is wrapped to that destination while conntrack only knows the first; a response wrapped from the second server is delivered to a receiver bound on that server's address (binds 127.0.0.60/61); untracked client ports still drop with counters. The harness winsock stub gained ioctlsocket/WSAIoctl/recvfrom/getpeername shims and a mswsock.h shim so `src/relay/udp.c` compiles under the test toolchain.

Verified with:

```sh
gcc -std=c11 -Wall -Wextra -D_WIN32 -DWINTPROXY_TEST_HOOKS -Itests/include -Iinc -Ilib tests/udp_framing_test.c src/relay/udp.c src/relay/socks5.c src/conntrack/conntrack.c -o build-tests/udp_framing_test && ./build-tests/udp_framing_test
```

plus the T1 command set and the conntrack roles suite; `cmake --build build-mingw -- -j4` passes.
