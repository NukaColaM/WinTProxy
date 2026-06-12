# Sender Preallocation And Block Hygiene

**Status**: done
**Serial**: T3
**Spec**: ../spec.md
**Depends on**: T1 (the executor flush shape settles how sender batches arrive, which fixes the preallocated request sizing and reuse points)

## Goal
Sender flushes stop heap-allocating per flush and packet blocks are cleared exactly once per pool cycle, removing redundant per-packet and per-flush memory work from the hot path.

## Acceptance
- [x] Each `ndisapi_sender_t` owns preallocated `ETH_M_REQUEST` storage and grouping scratch sized for `NDISAPI_BATCH_SIZE`, reused across flushes; no heap allocation occurs per sender flush (stub-verified).
- [x] Adapter-grouped send behavior, partial-send accounting, and send-failure counters are unchanged.
- [x] Packet blocks are cleared exactly once per pool cycle, at the point of use: `packet_parse` clears context, action constructors clear actions, and `ReadPackets` fills the buffer; acquire sets identity fields only (pool, adapter, refcount) and release pushes back without clearing. (Criteria refined from "owned by the release path" - use-time clearing is strictly fewer writes since parse and constructors already clear unconditionally.)
- [x] The `INTERMEDIATE_BUFFER` is not pre-cleared on acquire; `ReadPackets` content plus `m_Length` govern validity, and `packet_parse` / action constructors initialize context and action storage.
- [x] A block released on a parse-fail or short-read path is safely reusable with no stale context, action, or buffer state observable through the public packet path.

## Notes
Traceability: Story 1; technical decisions "Sender allocation" and "Block hygiene".

Today acquire memsets buffer+context+action and release memsets all three again (`src/ndisapi/adapter.c`), roughly 4 KB of redundant writes per packet; `ndisapi_send_batch_grouped` callocs the request and a used-array per flush. Pitfall: synthetic DNS response buffers (`free_after_send`) are heap-owned, not pool blocks - the sender release path must keep both ownership models working.

Implementation: `ndisapi_send_batch_grouped_with` takes caller storage; each sender allocates `send_request` (sized for `NDISAPI_BATCH_SIZE`) plus `group_scratch` at start and frees them at stop; `ndisapi_sender_send_items` flushes through that storage, so sender flushes allocate nothing (public `ndisapi_send_batch_to_*` keep their own temporary storage for direct callers). Pool acquire/release no longer memset buffer/context/action (~4 KB per packet removed); blocks only reach planning through a successful `ReadPackets` fill, and parse/constructors clear their own storage. Verified by `test_sender_flush_reuses_preallocated_request` (two flushes hit the driver with the same preallocated request pointer) and `test_packet_block_pool_skips_buffer_clearing_between_cycles` (frame byte survives a release/acquire cycle; identity fields are re-set).

Verified with the same commands as T1 (full suite plus `cmake --build build-mingw -- -j4` pass).
