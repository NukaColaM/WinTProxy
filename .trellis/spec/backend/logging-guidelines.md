# Logging Guidelines

> How logging is done in this project.

---

## Overview

WinTProxy uses a local async logger in `src/app/log.c` with public types and
macros declared in `inc/app/log.h`. Logger output always includes a timestamp,
thread ID, level label, and message. Stderr may use ANSI color when the console
supports it; file output never includes ANSI sequences.

Log level names and parsing are centralized in the logger implementation through
`log_level_name()`, `log_level_label()`, `log_level_allowed_names()`, and
`log_level_parse()`. Config parsing and config-dump output must use these helper
APIs instead of duplicating accepted strings.

---

## Log Levels

WinTProxy has exactly five public log levels, ordered from least to most verbose:

- `error` — startup/init failures, invalid config, unrecoverable subsystem errors.
- `warn` — recoverable degraded behavior, fallback paths, dropped work caused by
  missing required state or resource exhaustion.
- `info` — lifecycle start/stop, config summary, and listener binding summary.
  Default level; do not emit recurring metrics noise here.
- `debug` — normal troubleshooting view: proxy/direct rule outcomes, self-loop
  protection decisions, DNS query summaries, readable periodic performance
  snapshots, and moderate-volume diagnostic outcomes.
- `trace` — highest-volume diagnostics: relay/session lifecycle, packet rewrites,
  DNS TXID/NAT mapping internals, SOCKS5 handshake bytes, packet send/return
  traces, FLOW watcher internals, and other packet/protocol details.

Do not reintroduce a public `packet` level in config, docs, enums, or macros.
Former packet-level byte/rewriter diagnostics belong under `trace`; more selective
state-missing or decision-oriented diagnostics belong under `debug` or `warn`
depending on operator importance.

---

## Structured Logging

The logger is plain text, not JSON, but the format is consistent:

```text
[YYYY-MM-DD hh:mm:ss.mmm][TID:<id>][LEVEL] message
```

Required fields:

- local timestamp with milliseconds
- Windows thread ID
- fixed level label
- message text

Use the existing `LOG_ERROR`, `LOG_WARN`, `LOG_INFO`, `LOG_DEBUG`, and
`LOG_TRACE` macros so hot-path logs stay guarded by `log_is_enabled()`.

---

## What to Log

Log:

- process lifecycle (`starting`, `running`, shutdown)
- config summary at startup
- subsystem init/start failures
- proxy/direct rule outcomes and self-loop protection decisions at `debug`
- DNS query summaries at `debug` when DNS traffic is handled, including protocol,
  client source, original resolver, redirect/forward target when available, TXID,
  best-effort qname/qtype/qclass, action, and outcome
- readable grouped periodic performance snapshots at `debug` with capture,
  conntrack, process lookup, TCP relay, and UDP relay cumulative counters
- relay/session creation, teardown, DNS TXID rewrite details, SOCKS5 handshake
  bytes, FLOW watcher internals, packet send/return traces, and other
  high-volume packet-path diagnostics at `trace`

---

## What NOT to Log

Do not:

- log the same accepted log-level names in multiple places; use centralized helpers
- emit high-volume packet-path logs unguarded outside the logging macros
- put recurring performance snapshots at `info`; default logging should not grow
  steady metrics noise
- log PID 4/System FLOW watcher ignores at `debug`; keep them at `trace` or
  suppress/summarize them
- introduce a noisier-than-`trace` public level
- add ANSI color codes to file output
