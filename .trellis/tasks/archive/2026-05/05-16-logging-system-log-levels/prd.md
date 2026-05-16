# Refactor logging system and log levels

## Goal

Refactor WinTProxy's logging system into five levels — `error`, `warn`, `info`, `debug`, and `trace` — and make the resulting logs operationally useful. `debug` should be the normal troubleshooting level: it must show high-value flow decisions, DNS queries, and readable performance snapshots without drowning operators in low-value internal watcher noise. `trace` should remain the highest-volume packet/protocol detail level.

## What I already know

* The logging API lives in `inc/app/log.h` and `src/app/log.c`.
* The old runtime config accepted `error`, `warn`, `info`, `debug`, `trace`, and `packet`; the desired public level set is five levels only: `error`, `warn`, `info`, `debug`, and `trace`.
* The first implementation removed `packet`, centralized logger metadata/parsing, and clamped `-vvvv` to `trace`, but the resulting level allocation is not useful enough.
* Example issue from `/mnt/c/Users/Dev/Desktop/WinTProxy/WinTProxy.log`: repeated `Process flow event ignored: unknown [4] ...` lines are visible at `debug`; PID 4 is Windows `System`, and these FLOW watcher events are internal/noisy rather than normal troubleshooting decisions.
* User feedback: `DEBUG` should show DNS queries, and performance evaluations should be more readable and appear at `DEBUG` level.
* Current metrics logging is one long `LOG_INFO("perf: ...")` line every 30 seconds in `src/app/main.c`.
* DNS handling lives primarily in `src/dns/plan.c` and `src/dns/hijack.c`; packet context helpers cache DNS TXID but may not expose query names/types yet.

## Assumptions

* Do not add a third-party logging dependency.
* Keep the async logger design, file output behavior, and five-level CLI/config surface.
* Preserve default logging level `info`.
* Treat `trace` as the most verbose tier after removing `packet`.
* Relevel call sites based on operational usefulness and verbosity rather than changing traffic behavior.
* DNS query logging should not require full DNS parser complexity beyond safe best-effort extraction of query name/type/class from ordinary query payloads.

## Requirements

* Rebuild log levels around exactly five public levels: `error`, `warn`, `info`, `debug`, and `trace`.
* Remove the public `packet` tier from logger metadata, config parsing, docs, and log macros/call sites.
* Centralize log-level metadata and parsing enough to avoid drifting names between logger, config parser, and docs-adjacent behavior.
* Preserve accepted config levels for the new set: `error`, `warn`, `info`, `debug`, `trace`.
* Preserve default logging level `info`.
* Make `trace` the most verbose tier and use it for packet/protocol byte-level/high-volume diagnostics that previously required `packet`.
* Make `debug` the normal troubleshooting level:
  * Include proxy/direct decisions and self-loop protection decisions.
  * Include DNS query summaries at `debug` when DNS traffic is handled: protocol, client source, original resolver/redirect target where available, TXID, qname, qtype, and action/outcome.
  * Include readable periodic performance snapshots at `debug`, not `info`.
  * Keep `debug` clear of noisy internal implementation details that do not help normal troubleshooting.
* Make performance snapshots readable:
  * Replace the single long `perf:` line with grouped, easy-to-scan output.
  * Keep enough counters to evaluate packet capture, conntrack, process lookup, TCP relay, and UDP relay health.
  * Emit these snapshots at `debug`; `info` should not receive recurring metrics noise.
* Clean up unnecessary logs:
  * PID 4/System FLOW watcher ignore messages should not appear at `debug`; move them to `trace`, suppress them, or summarize them if useful.
  * Reassess all current `debug`/`trace` call sites after the five-level change and keep only logs that map to the level policy.
* Reallocate log call sites into reasonable levels:
  * `error`: startup/init failures, unrecoverable subsystem failures, config errors.
  * `warn`: recoverable degraded behavior, drops caused by resource exhaustion or missing required state, fallback paths worth operator attention.
  * `info`: lifecycle/start/stop/config summary and listener binding only; no recurring performance metrics.
  * `debug`: normal troubleshooting view — flow decisions, DNS query summaries, readable periodic performance snapshots, and moderate-volume diagnostic outcomes.
  * `trace`: relay/session lifecycle, packet rewrites, DNS TXID/NAT mapping internals, SOCKS5 handshake bytes, packet send/return traces, FLOW watcher internals, and other highest-volume diagnostics.
* Update user-facing docs/config comments to describe the five-level model and clarify `debug` vs `trace`.
* Keep hot-path logging guarded by `log_is_enabled` through existing macros.

## Acceptance Criteria

* [ ] Build succeeds with the existing CMake/MinGW workflow.
* [ ] Config parsing accepts `error`, `warn`, `info`, `debug`, and `trace`.
* [ ] Unknown config log levels are rejected with a clear message that lists the five accepted values.
* [ ] `-v`, `-vv`, and `-vvv` map monotonically from `info` through `trace`.
* [ ] Excess verbosity such as `-vvvv` clamps to `trace` and is documented.
* [ ] Logger output still includes timestamp, thread ID, level label, message, optional color on stderr, and optional file output without ANSI color codes.
* [ ] DNS queries are visible at `debug` with safe best-effort qname/qtype details.
* [ ] Periodic performance snapshots are visible at `debug`, are grouped/readable, and are no longer recurring `info` noise.
* [ ] Noisy PID 4/System FLOW watcher ignore lines do not appear at `debug`.
* [ ] No unguarded high-volume logging is introduced.
* [ ] Log level docs in `guide.md`, `README.md` if relevant, `config.example.json`, and `.trellis/spec/backend/logging-guidelines.md` match implementation.
* [ ] No `LOG_PACKET` call sites or public `packet` config docs remain, except possibly in migration/error text if intentionally retained.

## Definition of Done

* Tests/build checks run where available.
* Relevant Trellis spec/context is curated for implementation/check sub-agents.
* New logging conventions captured in `.trellis/spec/backend/logging-guidelines.md`.

## Out of Scope

* Adding structured JSON logging.
* Replacing the async logging queue with a new architecture.
* Adding log rotation, dynamic runtime level changes, syslog/EventLog output, or per-subsystem log filters.
* Changing traffic behavior or policy decisions.
* Adding new public log level aliases beyond the five-level set.
* Implementing a complete DNS message parser beyond safe query-summary logging needed for diagnostics.

## Technical Notes

* Likely impacted files: `inc/app/log.h`, `src/app/log.c`, `src/app/config.c`, `src/app/main.c`, DNS files (`src/dns/plan.c`, `src/dns/hijack.c`), process lookup (`src/process/lookup.c`), traffic subsystem `.c` files with `LOG_*` calls, `guide.md`, `README.md`, `config.example.json`, and `.trellis/spec/backend/logging-guidelines.md`.
* Backend specs inspected/curated: `.trellis/spec/backend/index.md`, `.trellis/spec/backend/directory-structure.md`, `.trellis/spec/backend/logging-guidelines.md`, `.trellis/spec/backend/quality-guidelines.md`, `.trellis/spec/backend/error-handling.md`, plus reuse/cross-layer thinking guides.
* Existing packet-level diagnostics likely move to `LOG_TRACE`; some decision-oriented messages should be `LOG_DEBUG` if useful during ordinary troubleshooting.
* Use the PID 4/System FLOW watcher log feedback as a concrete example of implementation detail that should not clutter `debug`.

## Technical Approach

1. Keep the five-level logger metadata/parsing model: only `LOG_ERROR`, `LOG_WARN`, `LOG_INFO`, `LOG_DEBUG`, and `LOG_TRACE`.
2. Add or reuse a safe helper for DNS query summary extraction so DNS query logs can include TXID, qname, qtype, and qclass without unsafe payload reads.
3. Add DNS query/action logs at `debug` at the point where the action/outcome is known; keep TXID/NAT rewrite internals at `trace`.
4. Replace the single long metrics line with grouped `LOG_DEBUG` performance lines, gated by `log_is_enabled(LOG_DEBUG)` to avoid snapshot/counter formatting work when disabled if practical.
5. Move or suppress FLOW watcher internals such as PID 4/System ignore messages out of `debug`.
6. Re-audit `LOG_DEBUG` and `LOG_TRACE` call sites for useful signal/noise separation.
7. Update docs/spec and run build verification.

## Decisions

* Legacy config value `packet` is rejected with a five-level error.
* CLI `-vvvv` and further repeated verbosity are harmlessly clamped to `trace`.
* `debug` is the normal troubleshooting level and must include DNS query summaries and readable performance snapshots.
