# Traffic Flow Refactor Options

## Scope and sources

Research for `.trellis/tasks/05-15-restructure-traffic-flow-path` based on local inspection of:

- `src/divert.c`
- `inc/divert.h`
- `inc/common.h`
- `inc/connection.h`
- `inc/dns.h`
- `inc/process.h`
- `inc/tcp_relay.h`
- `inc/udp_relay.h`
- `guide.md`
- `CMakeLists.txt`

No source code was edited.

## Current responsibilities

`src/divert.c` is the traffic-path center and currently mixes several distinct concerns:

1. **WinDivert adapter / engine lifecycle**
   - Builds the WinDivert filter string in `divert_start`.
   - Opens/closes the WinDivert handle.
   - Tunes queue parameters.
   - Detects loopback IfIdx.
   - Starts/join worker threads.
   - Owns a UDP forwarding socket for sending intercepted UDP payloads to the UDP relay.
   - Starts the DNS socket forwarder when loopback DNS forwarding is enabled.

2. **Packet receive/send primitives**
   - Receives raw packets in `divert_worker_proc`.
   - Parses IP/TCP/UDP headers using `WinDivertHelperParsePacket`.
   - Sends/reinjects packets through `divert_send_packet`.
   - Recalculates checksums after rewrites.
   - Counts received/sent/dropped/send-failure/UDP-forwarded packets.

3. **Packet context and low-level packet helpers**
   - Defines private `pkt_ctx_t` with raw packet pointer, headers, tuple, protocol, cached DNS payload/TXID.
   - Extracts DNS payload/TXID.
   - Clamps TCP MSS.
   - Sets loopback route metadata on `WINDIVERT_ADDRESS`.
   - Tests private IP ranges.
   - Allocates stable TCP relay source ports.

4. **Traffic classification**
   - `classify_packet` maps a parsed packet plus WinDivert address metadata to `pkt_type_t` from `inc/common.h`.
   - Classification is order-sensitive and covers:
     - TCP DNS return from redirected resolver.
     - UDP DNS responses via loopback socket path.
     - inbound packets and non-loopback DNS responses.
     - TCP/UDP relay return traffic.
     - self-proxy, self-relay, self-DNS bypass protections.
     - UDP/TCP DNS hijack candidates.
     - broadcast/multicast/private bypass.
     - default proxy/direct/block decision path.

5. **Inbound and return-path NAT**
   - Rewrites inbound DNS responses back to original DNS server tuple.
   - Rewrites TCP DNS return traffic using conntrack and DNS-loopback routing rules.
   - Rewrites TCP and UDP relay return traffic from loopback relay tuples back to original destination/client tuples.
   - Touches conntrack entries on return packets.

6. **DNS hijacking**
   - UDP DNS hijack either forwards DNS payload through a socket-based loopback forwarder or rewrites destination IP/port and stores DNS NAT metadata.
   - TCP DNS hijack creates conntrack and rewrites the TCP destination to the configured DNS redirect target.

7. **Proxy/direct/block decision path**
   - Performs process lookup with fast and retry paths.
   - Applies self-process exclusion after lookup.
   - Evaluates rules via `rules_match_ex`.
   - Implements direct and block decisions.
   - Implements proxy setup by adding conntrack entries and rewriting/forwarding traffic.

8. **Relay dispatch**
   - TCP proxy: rewrites packet source/destination to loopback relay tuple and reinjects.
   - UDP proxy: extracts UDP payload, prepends client IP/port framing, and sends to local UDP relay through a real UDP socket rather than WinDivert injection.
   - TCP non-SYN handling depends on existing conntrack; untracked proxied non-SYN packets are dropped to avoid leaks.

`inc/common.h` exposes `pkt_type_t`, but the type is only meaningful to the divert dispatcher. This creates a public/common enum for an internal traffic dispatcher concept.

## Existing documented traffic model

`guide.md` describes the packet flow as:

```text
Outbound packet → WinDivert filter → Process lookup → Rule evaluation
                                          ↓                  ↓
                                    DNS hijack?        proxy/direct/block
                                          ↓
                                    Conntrack lookup → NAT rewrite → Relay or reinject
```

The documentation is directionally correct but hides important implementation paths that matter for refactoring:

- return traffic is a first-class path, not only a conntrack lookup after rule evaluation;
- DNS has multiple paths: UDP non-loopback rewrite, UDP loopback socket forward, TCP DNS conntrack rewrite, DNS response restoration;
- bypass/self-protection decisions happen before rules for self endpoints and certain address classes, while self-process protection happens after process lookup;
- TCP and UDP proxy dispatch are substantially different.

## Repo constraints

1. **C11, Windows/MinGW, CMake**
   - `CMakeLists.txt` builds one executable from explicit source list.
   - Any new `.c` files must be added to `SOURCES`.
   - Include paths are `inc` and `lib`.

2. **WinDivert types are currently contained mostly in divert/process/dns areas**
   - `src/divert.c` and `src/process.c` include `windivert/windivert.h`.
   - `dns_hijack_start_forwarder` accepts a `void *divert_handle`, so DNS avoids exposing WinDivert handle type publicly.
   - Moving packet context into a public header may force broader WinDivert header exposure unless the header is carefully internal/private.

3. **Hot-path allocation principle**
   - `guide.md` says hot-path state uses fixed-size pools allocated at startup and no runtime allocation.
   - Refactor should avoid heap allocation per packet and keep packet context stack/local.

4. **Behavior is order-sensitive**
   - `classify_packet` explicitly warns: "Order matches the original monolithic worker exactly — do not reorder."
   - Classification order protects DNS return paths, relay return paths, self-proxy/self-relay/self-DNS, DNS hijack precedence, and bypasses.

5. **Shared mutable engine state**
   - `divert_engine_t` owns dependencies for config, conntrack, process lookup, DNS hijack, relay ports, UDP forwarding socket, counters, loopback IfIdx, and worker handles.
   - Multiple worker threads call the packet path concurrently.
   - New traffic modules must preserve thread-safety assumptions of existing subsystems.

6. **Relay protocols are externally separate**
   - `src/tcp_relay.c` and `src/udp_relay.c` already own SOCKS5 relay details.
   - Divert path should not absorb SOCKS5 handshake/session implementation, but it does need to prepare conntrack and dispatch packets/datagrams to relays.

7. **Public API currently small**
   - External startup code (`main.c`) only knows `divert_start`, `divert_stop`, and counters.
   - A complete refactor should preferably preserve this public API for CLI/config compatibility.

## Comparable module-decomposition patterns

### Pattern A: Thin capture adapter + traffic pipeline stages

**Shape**

- `divert.c`: engine lifecycle, filter construction, WinDivert receive/send, worker threads.
- `packet.c` / `packet.h`: packet context, parse/cache helpers, checksum/MSS/route helpers.
- `traffic_classify.c`: packet classification only.
- `traffic_dispatch.c`: top-level stage dispatcher, maps classification to handlers.
- `traffic_dns.c`: DNS hijack and DNS response handling.
- `traffic_nat.c` or `traffic_return.c`: relay/TCP DNS return-path restoration.
- `traffic_proxy.c`: process lookup, rule decision, conntrack setup, TCP/UDP proxy dispatch.

**Pros**

- Makes high-level stages visible from module names.
- Preserves the current packet flow with mostly mechanical extraction.
- Keeps WinDivert lifecycle separate from policy/NAT decisions.
- Enables incremental migration and diffable behavior preservation.

**Cons**

- Requires a shared internal context header that references WinDivert packet header/address types.
- If not disciplined, modules may all depend on `divert_engine_t`, creating a distributed monolith.
- Public/private header boundaries need care.

**Fit for this repo**: Best fit. The current code already has stage-like static functions; extraction is feasible without redesigning state ownership.

### Pattern B: Direction-first pipeline

**Shape**

- `capture` parses raw packets and determines direction.
- `outbound.c`: handles self/bypass/DNS hijack/process/rules/proxy/direct/block.
- `inbound.c`: handles inbound DNS response restoration and ordinary inbound pass.
- `return_path.c`: handles relay and TCP DNS return traffic.
- Common packet utilities remain separate.

**Pros**

- Aligns with transparent proxy mental model: outbound decisions vs return restoration.
- Reduces one large `pkt_type_t` switch into direction-specific handlers.
- Good readability for operators debugging traffic direction.

**Cons**

- Current classification includes loopback outbound return traffic, non-loopback inbound DNS, and loopback DNS response special cases; direction-only can obscure these important subpaths.
- DNS logic spans both outbound and inbound/return paths, risking duplication or cross-calls.
- Still needs a first-stage classifier for special return paths before normal outbound.

**Fit for this repo**: Good conceptual model, but should probably be expressed as documentation/handler grouping within Pattern A rather than the primary module split.

### Pattern C: Verdict/action engine

**Shape**

- Packet processing produces a `traffic_verdict_t` such as `PASS`, `DROP`, `REINJECT`, `REWRITE_AND_SEND`, `FORWARD_UDP_TO_RELAY`.
- Stages are pure-ish decision/transform functions that fill an action struct.
- A central executor performs all sends, drops, socket forwarding, counters, checksum updates.

**Pros**

- Separates decision logic from side effects.
- Easier to test decision results without WinDivert sends.
- Makes direct/block/proxy/bypass outcomes explicit.

**Cons**

- Larger behavior-preservation risk because current handlers interleave conntrack mutation, packet rewrites, sends, and counters.
- Action struct can become complex for raw packet mutation, address metadata, DNS forwarder calls, and UDP socket forwarding.
- Requires more design and likely more tests than this repo currently has.

**Fit for this repo**: Attractive long-term direction, but too invasive for a first complete refactor whose main goal is clarity without behavior changes.

### Pattern D: Protocol-specific handlers with common NAT services

**Shape**

- `tcp_path.c`: TCP DNS hijack, TCP proxy redirect, TCP return, TCP non-SYN behavior.
- `udp_path.c`: UDP DNS hijack, UDP proxy forwarding, UDP return.
- `dns_path.c` or shared DNS NAT service for cross-protocol DNS concepts.
- Shared `traffic_classify` and packet utilities.

**Pros**

- TCP and UDP behavior differences become explicit.
- Maps well to separate TCP and UDP relay modules.
- Helps maintain protocol-specific invariants (TCP SYN/non-SYN, MSS clamp, UDP payload framing).

**Cons**

- DNS crosses TCP and UDP and can be split awkwardly.
- Return-path restoration is similar enough that splitting may duplicate conntrack logic.
- The high-level traffic flow may become less visible if everything is protocol-first.

**Fit for this repo**: Useful as a sub-organization inside handler modules, but not the best top-level split.

## Feasible approaches

### Approach 1: Mechanical extraction from `divert.c`

Extract existing static functions into new modules with minimal semantic changes:

- `traffic_packet.[ch]`
  - `pkt_ctx_t` or renamed `traffic_packet_t`.
  - parse/init helper from raw packet + `WINDIVERT_ADDRESS`.
  - DNS payload/TXID cache helpers.
  - MSS clamp.
  - loopback route helper.
  - maybe private IP helper.

- `traffic_classify.[ch]`
  - `pkt_type_t` moved from `inc/common.h` to this module or renamed to `traffic_stage_t` / `traffic_path_t`.
  - `traffic_classify(engine, ctx, addr)`.

- `traffic_handlers.[ch]` or split below:
  - DNS handlers.
  - return/NAT handlers.
  - proxy decision/redirect handlers.

- `divert.c`
  - keeps `divert_start/stop/snapshot`, filter construction, worker loop, send wrapper, UDP forwarding socket ownership.
  - worker loop becomes: receive → parse/init context → classify → dispatch.

This is the lowest-risk path and can be completed in phases.

### Approach 2: New traffic-flow facade behind existing divert engine

Create `traffic_flow.[ch]` with a single public internal entrypoint:

```c
void traffic_flow_handle_packet(divert_engine_t *engine, uint8_t *packet,
                                UINT packet_len, WINDIVERT_ADDRESS *addr);
```

Then move parsing, classification, dispatch, and handlers under this facade. `divert_worker_proc` becomes very small and only calls the facade.

This can later be decomposed into submodules. It gives an immediate architectural seam, but a single `traffic_flow.c` could simply become the new monolith unless it is split further.

### Approach 3: Full verdict/action redesign

Introduce explicit stage output objects and executor. This could enable unit tests and cleaner side-effect boundaries, but it changes control flow significantly and carries high packet-path regression risk. Not recommended as the first implementation for this task.

### Approach 4: Protocol-first split

Move TCP-specific and UDP-specific handlers out of `divert.c` while keeping classification in place. This improves some readability but does not make the complete traffic path as explicit as the task asks, because lifecycle, classification, policy, DNS, NAT, and dispatch remain intermixed.

## Recommended approach

Use **Pattern A with a small facade**, implemented as a mostly mechanical extraction:

1. Keep public API stable:
   - `inc/divert.h` remains the public engine API used by `main.c`.
   - `divert_start`, `divert_stop`, and `divert_snapshot_counters` behavior should not change.

2. Introduce internal traffic modules:
   - `inc/traffic_packet.h` + `src/traffic_packet.c` for packet context and packet mutation helpers.
   - `inc/traffic_classify.h` + `src/traffic_classify.c` for ordered classification.
   - `inc/traffic_flow.h` + `src/traffic_flow.c` for dispatch and high-level handler orchestration.
   - Optionally split handler implementation further once compiling:
     - `src/traffic_dns.c`
     - `src/traffic_return.c`
     - `src/traffic_proxy.c`

3. Move `pkt_type_t` out of `inc/common.h` if possible:
   - It is not a global/common concept; it belongs to traffic classification.
   - Rename to `traffic_path_t` or keep `pkt_type_t` in `traffic_classify.h` for smaller diff.
   - If moving it creates excessive churn, defer until after mechanical extraction.

4. Keep `divert_engine_t` as the shared dependency container initially:
   - This avoids redesigning state ownership and keeps startup/lifecycle simple.
   - To prevent distributed monolith drift, helper APIs should accept narrower arguments where easy, but do not force it in the first migration.

5. Preserve current order exactly:
   - Move `classify_packet` body unchanged first.
   - Keep the same `switch` mapping from `pkt_type_t` to handlers.
   - Keep comments marking order-sensitive behavior.

6. Update docs after code shape stabilizes:
   - `guide.md` packet flow should show capture, parse/classify, special return/DNS paths, policy decision, NAT/relay dispatch, and reinjection.
   - Mention module names so readers can map docs to code.

Suggested final source layout:

```text
src/divert.c             WinDivert lifecycle, filter, workers, recv/send primitives
src/traffic_packet.c     packet context, parsing/cache, checksums/MSS/route helpers
src/traffic_classify.c   ordered traffic-path classification
src/traffic_flow.c       top-level dispatcher and shared send/drop helpers
src/traffic_dns.c        UDP/TCP DNS hijack and DNS response restoration
src/traffic_return.c     relay/TCP-DNS return NAT rewrite
src/traffic_proxy.c      process/rules decisions, conntrack setup, relay dispatch
```

If that many files feels too broad for one change, start with:

```text
src/divert.c
src/traffic_packet.c
src/traffic_classify.c
src/traffic_flow.c
```

and split `traffic_flow.c` into DNS/return/proxy files once behavior is preserved.

## Migration risks

1. **Classification order regressions**
   - Reordering DNS return, relay return, self bypass, DNS hijack, and general proxy classification can create loops, leaks, or missed DNS restoration.
   - Mitigation: copy classification unchanged first; add comments/tests or a checklist around each `pkt_type_t` case.

2. **WinDivert address metadata mistakes**
   - `Outbound`, `Loopback`, `Network.IfIdx`, and `Network.SubIfIdx` are essential for correct reinjection.
   - Mitigation: keep route-setting helpers centralized and preserve current call sites.

3. **Conntrack key mismatches**
   - TCP uses full 5-tuple-ish keys and a relay source port; UDP uses a simpler client-port path plus loopback alias key.
   - TCP DNS hijack uses conntrack differently from ordinary TCP proxying.
   - Mitigation: do not redesign conntrack APIs during the first refactor; move call blocks intact.

4. **UDP proxy dispatch confusion**
   - UDP proxy traffic is not rewritten and reinjected like TCP; it is sent to the UDP relay over `engine->udp_fwd_sock` with a custom 6-byte source framing header.
   - Mitigation: name this path explicitly (`traffic_proxy_forward_udp_to_relay_socket`) and document it.

5. **DNS loopback vs non-loopback split**
   - Loopback DNS uses socket forwarding and no extra inbound filter clause; non-loopback DNS uses packet rewrite and inbound response capture.
   - Mitigation: keep DNS forwarding lifecycle in `divert_start` or clearly document if moved.

6. **Header dependency spread**
   - New public headers that expose WinDivert types can increase compile coupling.
   - Mitigation: internal headers are acceptable in `inc/` for this project, but keep them narrowly named and avoid including them from unrelated modules.

7. **Counter semantics drift**
   - Drops are counted manually in several handlers; sends/failures are counted in the send wrapper; UDP forwarded is counted on socket send success.
   - Mitigation: keep a single send/drop/UDP-forward helper and do not count direct returns twice.

8. **Build integration omissions**
   - New `.c` files must be added to `CMakeLists.txt` `SOURCES`.
   - Mitigation: add all new modules in one CMake edit and run the documented MinGW/CMake build or closest available local configure/build.

9. **Behavior masked by lack of tests**
   - The repo appears to rely mainly on build validation and runtime behavior; no test harness was found in inspected files.
   - Mitigation: use a low-risk mechanical extraction, compare control flow before/after, and update `guide.md` to encode invariants.

## Implementation checklist for handoff

- [ ] Read `.trellis/spec/backend/index.md` and linked backend guidelines before coding.
- [ ] Add internal traffic module headers/sources.
- [ ] Move packet context/helpers first and compile.
- [ ] Move classifier unchanged and compile.
- [ ] Move dispatcher/handlers unchanged and compile.
- [ ] Remove `pkt_type_t` from `inc/common.h` or justify keeping it temporarily.
- [ ] Update `CMakeLists.txt` source list.
- [ ] Update `guide.md` architecture packet-flow section.
- [ ] Run available CMake/MinGW build validation.
