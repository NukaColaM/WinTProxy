# Directory Structure

> How backend code is organized in this project.

---

## Overview

WinTProxy is organized as explicit C subsystems under matching `src/` and `inc/`
subdirectories. The packet path is intentionally split by responsibility so the
WinDivert adapter, packet parsing, flow planning, action execution, DNS handling,
policy matching, path planning, conntrack, process lookup, and relays do not
collapse into one traffic monolith.

When adding packet-path behavior, place code in the subsystem that owns the
responsibility, not in `divert/adapter.c` by default.

---

## Directory Layout

```text
src/
├── app/          # CLI/config/logging bootstrap and main program
├── conntrack/    # Connection tracking state and lookup/update APIs
├── core/         # Shared constants, common error codes, tiny utilities
├── divert/       # WinDivert adapter: filters, queue tuning, workers, I/O counters
├── dns/          # UDP/TCP DNS hijack planning, DNS NAT/TXID state, DNS forwarding
├── flow/         # Verdict/action objects, planner orchestration, action executor
├── packet/       # Packet context parsing, cached payload/TXID, packet mutation helpers
├── path/         # Packet path planning: bypass, proxy setup, return restoration
├── policy/       # Proxy/direct policy rules and matching
├── process/      # Packet-to-process ownership lookup
└── relay/        # SOCKS5 protocol helpers and TCP/UDP relay implementations

inc/
└── <same subsystem folders with public/internal headers>
```

The current CMake build lists source files explicitly. When adding or moving a
`.c` file, update `CMakeLists.txt` in the same change.

---

## Module Organization

### WinDivert adapter boundary

`divert/adapter.c` owns capture mechanics only:

- WinDivert filter construction and handle lifecycle
- queue parameter tuning
- worker receive loop
- adapter-level send/reinject helpers and counters
- relay/DNS forwarding sockets that are adapter I/O resources

It should not grow policy matching, DNS NAT logic, conntrack planning, or relay
routing decisions. The worker loop should parse a packet, ask `flow/plan` for an
action, and execute that action.

### Verdict/action flow boundary

`flow/` owns the packet outcome contract:

- `flow/plan.*` orchestrates ordered stage planning.
- `flow/action.*` defines explicit final outcomes.
- `flow/executor.*` performs centralized final side effects.

Planner stages may perform required lookups/reservations, such as process lookup,
conntrack reservation, DNS NAT reservation, and relay source-port allocation. Final
packet outcomes must still be represented as explicit actions before side effects:
pass/reinject, drop, rewrite/send, UDP relay forward, or DNS forward.

### Packet helpers

`packet/` owns raw packet view/mutation helpers:

- parse IP/TCP/UDP headers into stack-local packet contexts
- cache payload and DNS TXID extraction
- recalculate checksums after mutation
- set address/route metadata helpers when appropriate
- clamp TCP MSS when proxy/return paths require it

Do not allocate per packet on the heap in this layer.

### Path planning

`path/` owns non-DNS packet-path decisions:

- `classify.*` performs ordered traffic classification.
- `bypass.*` plans explicit non-proxyable/direct outcomes.
- `proxy.*` performs process lookup, policy decision, conntrack setup, and relay
action planning.
- `return.*` restores TCP/UDP return traffic from conntrack.

DNS traffic is planned under `dns/`, not mixed into ordinary proxy policy.

### DNS, conntrack, process, relay

- `dns/` owns DNS hijack, DNS NAT/TXID state, TCP/UDP DNS planning, and DNS
  loopback/socket forwarding.
- `conntrack/conntrack.*` is a first-class subsystem because proxy and return
  paths depend on its keys and lifetime.
- `process/lookup.*` owns packet-to-process ownership lookup and self-process
  checks.
- `relay/` owns SOCKS5 TCP CONNECT, UDP ASSOCIATE, and relay sessions. Flow/path
  modules may prepare/forward to relays, but should not implement SOCKS5 protocol
  details.

---

## Config and CLI Contracts

The runtime config uses a traffic-stage schema. Top-level sections are:

```json
{
  "capture": {},
  "dns": {},
  "bypass": {},
  "policy": {},
  "proxy": {},
  "logging": {}
}
```

Policy is proxy/direct only:

```json
{
  "policy": {
    "default_decision": "proxy",
    "rules": [
      {
        "process": "chrome.exe,firefox.exe",
        "protocol": "tcp",
        "port": "80,443",
        "decision": "proxy"
      }
    ]
  }
}
```

Do not reintroduce policy-level `block` without a new product decision. Unknown
config keys should fail validation rather than being silently ignored; `_comment`
keys are allowed for annotated examples.

The CLI is intentionally minimal. Traffic behavior belongs in config. CLI options
should stay focused on config path, logging overrides/verbosity, version, and help.

---

## Naming Conventions

- Use subsystem include paths, e.g. `#include "flow/plan.h"` and
  `#include "conntrack/conntrack.h"`.
- Use `path/` for bypass/proxy/return packet-path planning.
- Use `process/lookup.*` for process ownership lookup.
- Use `conntrack/conntrack.*`, not a generic `state/` folder.
- Avoid broad `traffic.*` files or folders; split by responsibility instead.

---

## Common Mistakes

### Putting decisions back into the adapter

**Wrong**: Add a new DNS/policy/proxy branch directly to `divert/adapter.c`.

**Correct**: Add the classification/planning logic to `dns/`, `path/`, or
`policy/`, return a `traffic_action_t`, and let `flow/executor.c` perform the
final side effect.

### Hiding behavior in the WinDivert filter

The capture filter may exclude unavoidable low-level system traffic, but traffic
semantics such as non-proxyable/private/broadcast/multicast decisions should be
visible in path planning when practical. This keeps docs, config, and code aligned.

### Silently accepting old config shapes

Because the config schema is a stage contract, unknown legacy keys such as
`rules`, `default_action`, `log_level`, `bypass_private_ips`, or policy rule
`action` should fail validation. Silent acceptance causes cross-layer drift between
configuration, docs, and the flow engine.
