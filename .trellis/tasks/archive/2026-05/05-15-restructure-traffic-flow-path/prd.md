# Restructure Traffic Flow Path

## Goal

Restructure the project around a complete, rational, and explicit traffic-flow architecture so that packet capture, classification, DNS handling, proxy/direct policy decisions, NAT/conntrack rewrites, relay forwarding, reinjection, and side-effect execution are easier to reason about and maintain. The verdict/action engine is the central abstraction for the new flow, not the whole scope by itself.

## What I already know

* The user wants to restructure the current project, focused on rationality of the traffic flow path.
* WinTProxy is a C/WinDivert transparent SOCKS5 proxy for IPv4 TCP and UDP.
* Current architecture is centered around `src/divert.c`, which captures packets, classifies packet type, performs DNS hijack, rule evaluation, conntrack/NAT rewrite, relay forwarding, and reinjection dispatch.
* Relays live in `src/tcp_relay.c` and `src/udp_relay.c`; state lives in `src/connection.c`, `src/dns.c`, and `src/process.c`.
* Documentation currently describes packet flow as: WinDivert filter → process lookup → rule evaluation → DNS hijack? → conntrack lookup → NAT rewrite → relay or reinject.

## Assumptions (temporary)

* Primary objective is code organization and flow clarity, not new proxy functionality.
* Original behavior is a reference point, not a compatibility contract; intentional traffic semantics, module APIs, CLI flags, and config schema may change when the new flow model is clearer or safer.
* There is no compatibility requirement for this refactor; compatibility-preserving choices are optional, not constraints.
* The most likely hotspot is decomposing or re-layering `src/divert.c`, because it currently owns many stages of the traffic path.

## Research References

* [`research/traffic-flow-refactor-options.md`](research/traffic-flow-refactor-options.md) — compares extraction/facade/verdict options; the user selected the verdict/action engine despite the higher implementation risk because this task prioritizes complete architecture rationality over compatibility-preserving extraction.

## Research Notes

### Feasible approaches

**Approach A: Thin WinDivert adapter + explicit traffic modules** (recommended)

* `src/divert.c` stays responsible for WinDivert lifecycle, filter construction, queue tuning, worker threads, and receive/send primitives.
* New traffic modules make the packet path visible: packet context/helpers, ordered classification, flow dispatch, DNS handling, return/NAT handling, proxy/direct/block handling.
* Pros: clear architecture, manageable migration, preserves existing public `divert_*` API.
* Cons: requires careful internal headers and discipline so `divert_engine_t` does not become a distributed monolith.

**Approach B: Traffic-flow facade first**

* Introduce `traffic_flow_handle_packet(...)` behind the current divert worker, then split internally over time.
* Pros: immediate seam and smaller first diff.
* Cons: risks simply moving the monolith from `divert.c` to `traffic_flow.c` unless followed by further splits.

**Approach C: Verdict/action engine**

* Convert processing into explicit verdict objects (`pass`, `drop`, `rewrite/send`, `forward UDP`) plus an executor.
* Pros: clean side-effect boundaries and testability.
* Cons: high control-flow churn and higher regression risk for a behavior-preserving refactor.

## Open Questions

* None currently; proceed with recommended implementation details for remaining naming/layout choices unless new product/behavior questions arise.

## Decision (ADR-lite)

**Context**: The current packet path mixes classification, policy decisions, packet mutation, conntrack/DNS state changes, relay forwarding, counters, and WinDivert reinjection inside `src/divert.c`. A complete refactor should make traffic outcomes explicit rather than just moving functions into new files.

**Decision**: Use **Approach C: Verdict/action engine**. Packet processing should produce explicit traffic actions/verdicts such as pass/reinject, drop, rewrite-and-send, forward UDP-to-relay, DNS forward, or stateful setup plus send. A separate executor should own side effects where practical.

**Consequences**: This gives the clearest long-term traffic model and better testability, but it has higher implementation risk because current handlers interleave state mutation, packet rewrites, counters, and sends. Original behavior should be used as a reference for expected scenarios, not a constraint. The new design may intentionally change traffic semantics, internal APIs, CLI flags, and config schema when that makes the flow more rational; such changes must be documented in the PRD/docs.

## Feature Decisions

* DNS hijacking is a core purpose/highlight of the project and must be retained for both UDP DNS and TCP DNS, but the implementation and flow model may be redesigned.
* UDP SOCKS5 UDP ASSOCIATE proxying must remain a first-class supported traffic path, but relay dispatch and local framing/session boundaries may be redesigned.
* The policy model should be simplified to **proxy/direct only**. Remove the `block` action from the new traffic-flow model unless a later discussion reintroduces denial as a separate concept.
* Private, broadcast, and multicast destination bypasses should be retained, but modeled explicitly as non-proxyable/direct traffic verdicts in the new flow.
* Self-protection should be redesigned freely. The new architecture must prevent self-proxy, relay-loop, and DNS-loop failures, but it does not need to preserve the current endpoint/process bypass categories exactly.
* CLI and config schema should be redesigned now to match the new architecture; no compatibility with the existing config shape is required.
* The redesigned config should use a **traffic-stage schema** whose top-level sections mirror the flow, e.g. capture, DNS, policy, bypass/non-proxyable destinations, proxy, and logging.
* Policy rules in the new config should use direct action decisions: ordered first-match rules with `decision: "proxy" | "direct"` plus a proxy/direct default decision.
* CLI should be minimal: traffic behavior belongs in config; CLI should focus on `--config`, logging overrides if needed, `--version`, and `--help` rather than preserving proxy/DNS traffic overrides.
* DNS hijacking should be a first-class stage before normal proxy/direct policy: when enabled, matching TCP/UDP DNS traffic is handled by the DNS stage before policy rules.
* For DNS traffic, DNS hijacking should run before private/broadcast/multicast bypass checks; non-DNS traffic still uses explicit non-proxyable/direct bypass verdicts before normal policy.
* The verdict/action engine should use a pragmatic planner/executor split: stages may perform required state lookups/reservations (process lookup, conntrack, DNS NAT), but final packet outcomes such as pass/reinject, drop, rewrite/send, UDP relay forwarding, and DNS forwarding should go through explicit traffic actions and an executor.
* The refactor should avoid creating one broad `traffic` module/folder that becomes a new monolith; split the traffic-flow architecture into multiple explicit submodules aligned with stages/responsibilities.
* Use `path` naming for the packet-path planning modules that handle bypass/non-proxyable traffic, proxy path setup, and return-path restoration.
* Existing supporting subsystems should be moved into the new explicit multi-submodule layout too, not left as flat root-level files when they belong to DNS, relay, state, process, or policy responsibilities.
* Conntrack should be a first-class subsystem under `conntrack/conntrack.*`, not hidden in a generic `state/` folder.
* Use recommended names for remaining implementation details without further user prompts unless they affect behavior/product scope; e.g. `process/lookup.*` for process ownership lookup.


## Technical Approach

Use the recommended detailed design without further naming/layout prompts unless a product behavior decision is required:

* Folder layout:
  * `app/` for config/logging bootstrap code.
  * `core/` for common constants/utilities.
  * `divert/` for the WinDivert adapter: filter construction, queue tuning, worker receive/send lifecycle, counters, and adapter-level I/O.
  * `packet/` for packet context, parsing, cached payload/TXID access, checksum/MSS/address mutation helpers.
  * `flow/` for the verdict/action engine, planner orchestration, and action executor.
  * `dns/` for UDP/TCP DNS hijack, DNS NAT/TXID state, and DNS loopback/socket forwarding.
  * `policy/` for proxy/direct policy rule compilation and matching.
  * `path/` for bypass/non-proxyable planning, proxy path setup, and return-path restoration.
  * `conntrack/` for connection tracking.
  * `process/lookup.*` for packet-to-process ownership lookup.
  * `relay/` for TCP relay, UDP relay, and SOCKS5 protocol helpers.
* Use a pragmatic planner/executor split:
  * Stage planners may perform required lookups/reservations such as process lookup, conntrack lookup/reservation, DNS NAT reservation, and relay source-port allocation.
  * Final packet outcomes must be represented as explicit actions and executed centrally: pass/reinject, drop, rewrite/send, forward UDP-to-relay, DNS forward, and return-path restore/send.
* Redesign config as a traffic-stage schema and update `config.example.json`, README, and guide:
  * Minimal CLI focused on config/logging/help/version.
  * Config sections mirror stages: capture, dns, bypass/non-proxyable, policy, proxy, logging.
  * Policy is ordered first-match rules with `decision: "proxy" | "direct"` and a proxy/direct default.
* Retain TCP proxy, UDP proxy, and both UDP/TCP DNS hijacking, but redesign their flow and APIs freely.
* Remove policy-level `block` from the new model.
* Keep private/broadcast/multicast bypass as explicit non-proxyable/direct outcomes.
* Redesign self/loop protection freely while preventing self-proxy, relay-loop, and DNS-loop failures.

## Requirements (evolving)

* Make the traffic path explicit and rational in code structure.
* Perform a complete refactoring of the traffic-flow architecture rather than a narrow `src/divert.c` cleanup or a verdict enum added to the existing monolith.
* Use a verdict/action traffic engine as the organizing abstraction for packet outcomes and side effects.
* Rework module boundaries around the traffic stages: WinDivert adapter, packet context/parsing, classification, policy/rule decision, DNS handling, NAT/conntrack return handling, relay dispatch, and action execution.
* Split these responsibilities into multiple explicit submodules rather than one generic `traffic` module/folder.
* Prefer a multi-folder layout such as `divert/`, `packet/`, `flow/`, `dns/`, `policy/`, `path/`, and `relay/`; `path/` is the chosen name for bypass/proxy/return path planning.
* Relocate supporting subsystems into the new layout as part of the complete refactor, e.g. relays under `relay/`, DNS implementation under `dns/`, conntrack under `conntrack/`, and process helpers under explicit domain folders.
* Update architecture documentation and naming where module boundaries or traffic-flow concepts change.
* Use the original behavior as a reference for supported scenarios, not as a strict line-by-line compatibility contract.
* Do not preserve compatibility for its own sake; internal APIs, file layout, CLI flags, config schema, and traffic semantics may change if the new architecture is more coherent.
* Redesign CLI/config schema as part of this refactor so user-facing configuration reflects the proxy/direct-only traffic model and explicit DNS/proxy/bypass stages.
* Use a traffic-stage config schema rather than the current flat/current-like schema; top-level sections should align with the new flow stages.
* Make policy rules direct and explicit: first-match ordered rules return `proxy` or `direct`; the default policy decision is also `proxy` or `direct`.
* Redesign CLI as minimal config/bootstrap interface rather than a parallel traffic-configuration surface.
* Explicitly document any intentional behavior/interface changes introduced by the new traffic-flow model.
* Existing supported scenarios must be considered in the new engine, either retained or proposed for removal/simplification with explicit user discussion and documented rationale:
  * TCP SOCKS5 CONNECT proxying.
  * UDP SOCKS5 UDP ASSOCIATE proxying. Retain as a first-class path; redesign is allowed.
  * UDP and TCP DNS hijacking. Retain both; redesign is allowed and expected if it improves the flow architecture.
  * Direct/proxy rule decisions. Simplify policy to proxy/direct only; remove the current `block` action from the refactored model.
  * Self/loop protection. Redesign freely; the new flow must prevent self-proxy, relay-loop, and DNS-loop failures, but need not preserve current self-proxy/self-relay/self-DNS/process-owned bypass categories exactly.
  * Private/broadcast/multicast bypass rules. Retain and model explicitly as non-proxyable/direct verdicts.
  * Fixed-size hot-path state and startup allocation principles.

## Acceptance Criteria (evolving)

* [ ] A reader can identify the high-level traffic stages from code/module names without reading one monolithic packet worker.
* [ ] Any CLI/config/API or traffic-behavior changes are deliberate and documented.
* [ ] TCP, UDP, DNS hijack, bypass, direct, proxy, and proxy return paths are all considered in the new structure, either retained or explicitly removed/changed after discussion with documented rationale.
* [ ] Project builds successfully with the documented CMake/MinGW flow or the closest available local build command.
* [ ] README/guide architecture text is updated if module boundaries or flow diagrams change.

## Definition of Done (team quality bar)

* Tests added/updated where practical, or build/static validation performed if no test harness exists.
* Lint/typecheck/build green for available project tooling.
* Docs/notes updated if architecture or behavior documentation changes.
* Rollback considered because this touches packet-path code.

## Out of Scope (explicit)

* New proxy protocols beyond SOCKS5.
* IPv6 support.
* Authentication support.
* Replacing WinDivert or the Windows-only runtime model.

## Technical Notes

* Files inspected: `README.md`, `guide.md`, `src/main.c`, `inc/divert.h`, `src/divert.c`, `inc/connection.h`, `inc/tcp_relay.h`, `inc/udp_relay.h`, `inc/dns.h`.
* Current `src/divert.c` contains `pkt_ctx_t`, packet classification, DNS response handling, TCP DNS handling, return path rewrite, DNS hijack, UDP forwarding socket framing, proxy conntrack setup, TCP non-SYN handling, and worker loop dispatch.
* `guide.md` has the canonical architecture section and packet flow diagram that should stay aligned with code.
