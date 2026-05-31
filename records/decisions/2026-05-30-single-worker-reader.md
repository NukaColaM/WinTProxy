# Single-worker ndisapi reader (not multi-worker)

**Date**: 2026-05-30

## Context

The original WinDivert engine used `DIVERT_WORKER_COUNT=4` threads, each calling `WinDivertRecv` on a shared handle. WinDivert's handle model ensures each packet reaches exactly one caller. ndisapi's `ReadPacketsUnsorted` has different semantics: it delivers ALL pending packets from ALL filtered adapters to every caller. Multiple workers racing on the same event would each receive full copies of every batch, causing 4× packet duplication.

Proxifyre validates this: it uses a single reader thread for `ReadPacketsUnsorted`, then pipelines to separate process/write threads via queues.

## Decision

**Use `NDISAPI_WORKER_COUNT = 1` (single reader thread).** The worker reads batches, processes inline (planner → executor), and dispatches via batch send. If throughput demands it later, add a pipeline with queue-per-stage separation, not multiple reader threads.

## Why not alternatives

- **Multiple reader threads** — rejected because `ReadPacketsUnsorted` delivers full copies to all concurrent callers, producing massive packet duplication. Each worker would need its own independent adapter event/handle set, which ndisapi does not support for unsorted reads.
- **Per-worker adapter partitioning** — rejected because adapter handles can't be partitioned for unsorted reads; the unsorted API reads from all adapters at once.
