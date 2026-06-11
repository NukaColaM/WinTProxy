# NDISAPI ReadPackets Research

**Date**: 2026-06-11
**Prompted by**: Q1, Q8, NDISAPI documentation review

## What was investigated
Official NT Kernel WinpkFilter/NDISAPI documentation and the upstream `wiresock/ndisapi` examples were reviewed to determine whether WinTProxy can replace its shared `ReadPacketsUnsorted` ingress with a multi-worker architecture based on adapter-specific `ReadPackets`.

## Findings
`ReadPacketsUnsorted` is documented as reading "any available packets from the driver packets queue" and returning each packet's adapter handle in `INTERMEDIATE_BUFFER::m_hAdapter`. The public documentation does not state that concurrent `ReadPacketsUnsorted` callers safely partition packets.

`ReadPackets` is documented as adapter-specific. The caller initializes `ETH_M_REQUEST::hAdapterHandle`, and packets are extracted from the network-interface-associated packet queue.

`SetPacketEvent` is also adapter-specific. The driver signals the supplied event when the adapter-associated packet queue is non-empty.

`GetAdapterPacketQueueSize` and `FlushAdapterPacketQueue` operate on a requested adapter handle, which supports adapter-local overload handling in the replacement design.

`InitializeFastIo` and `AddSecondaryFastIo` support shared-memory packet transfer, with up to 16 Fast I/O sections after initialization. The official wording says packets fall back to the internal queue when shared memory is unavailable or an application read operation is in progress. Upstream's Fast I/O example allocates multiple sections but drains them from one worker thread, so Fast I/O does not establish a documented phase 1 multi-reader contract.

The upstream queued packet filter uses one adapter-specific reader, one processing thread, and dedicated writer threads. The upstream dual packet filter uses separate working threads for separate adapter handles. No upstream example was found that runs concurrent `ReadPacketsUnsorted` readers.

## Implications
The phase 1 replacement should use adapter-specific `ReadPackets` with per-adapter events, buffers, and reader threads instead of trying to make `ReadPacketsUnsorted` concurrent.

The old unsorted ingress should be removed from production code rather than hidden behind a fallback because the user explicitly rejected fallback behavior.

Adapter-local queue size and flush APIs can be used for bounded overload handling when user-mode packet-block pool capacity is exhausted.

Fast I/O should remain out of phase 1. It may be revisited after the adapter-sharded `ReadPackets` architecture is correct and live-driver behavior is validated.
