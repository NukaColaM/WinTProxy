/*
 * ndisapi packet engine implementation.
 *
 * Captures Ethernet-level traffic from every network adapter using
 * ndisapi.dll's adapter-specific C API. Each adapter reader reads batches
 * of packets, parses them, and dispatches them via the flow planner/executor.
 *
 * In T1 (this task), all packets pass through unmodified (ON_SEND →
 * adapter, ON_RECEIVE → MSTCP).  Classification and proxy rewrite are
 * wired in T2–T5.
 */
#include "ndisapi/adapter.h"
#include "ndisapi/ndisapi.h"    /* vendored C API */
#include "flow/executor.h"
#include "flow/plan.h"
#include "packet/context.h"
#include "app/log.h"
#include "core/util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

void ndisapi_counter_inc(volatile LONG64 *counter) {
    InterlockedIncrement64(counter);
}

void ndisapi_count_drop(ndisapi_engine_t *engine) {
    ndisapi_counter_inc(&engine->counters.packets_dropped);
}

void ndisapi_count_udp_forwarded(ndisapi_engine_t *engine) {
    ndisapi_counter_inc(&engine->counters.udp_forwarded);
}

static void ndisapi_count_overload_drop(ndisapi_engine_t *engine) {
    ndisapi_counter_inc(&engine->counters.overload_drops);
    ndisapi_count_drop(engine);
}

uint16_t ndisapi_next_tcp_relay_src_port(ndisapi_engine_t *engine) {
    LONG next = InterlockedIncrement(&engine->next_tcp_relay_src_port);
    LONG span = (LONG)WTP_TCP_RELAY_SRC_PORT_MAX - (LONG)WTP_TCP_RELAY_SRC_PORT_MIN + 1L;
    LONG offset;

    if (span <= 0) return WTP_TCP_RELAY_SRC_PORT_MIN;

    offset = (next - 1L) % span;
    if (offset < 0) offset += span;

    return (uint16_t)((LONG)WTP_TCP_RELAY_SRC_PORT_MIN + offset);
}

static void ndisapi_counter_add(volatile LONG64 *counter, LONG64 value) {
    if (value > 0) {
        InterlockedAdd64(counter, value);
    }
}

/* ------------------------------------------------------------------ */
/*  Packet block pool                                                 */
/* ------------------------------------------------------------------ */

/*
 * Pool capacity covers the maximum simultaneous downstream occupancy: blocks
 * in flight inside readers plus every flow-worker and sender queue slot, so
 * pool exhaustion means systemic overload rather than a single stalled stage.
 */
DWORD ndisapi_packet_pool_capacity_for(DWORD adapter_count,
                                       DWORD flow_worker_count) {
    DWORD reader_in_flight = adapter_count * (DWORD)NDISAPI_BATCH_SIZE * 2U;

    return reader_in_flight +
           flow_worker_count * (DWORD)NDISAPI_FLOW_QUEUE_DEPTH +
           (DWORD)NDISAPI_SENDER_COUNT * (DWORD)NDISAPI_SENDER_QUEUE_DEPTH;
}

int ndisapi_packet_pool_init(ndisapi_packet_pool_t *pool, DWORD capacity) {
    DWORD i;

    if (!pool || capacity == 0) return 0;

    memset(pool, 0, sizeof(*pool));
    InitializeSRWLock(&pool->lock);
    pool->free_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!pool->free_event) return 0;
    pool->blocks = (ndisapi_packet_block_t *)
        calloc((size_t)capacity, sizeof(pool->blocks[0]));
    if (!pool->blocks) {
        CloseHandle(pool->free_event);
        pool->free_event = NULL;
        return 0;
    }

    pool->capacity = capacity;
    pool->free_count = capacity;
    for (i = 0; i < capacity; i++) {
        ndisapi_packet_block_t *block = &pool->blocks[i];
        block->pool = pool;
        block->next = pool->free_list;
        pool->free_list = block;
    }

    return 1;
}

void ndisapi_packet_pool_destroy(ndisapi_packet_pool_t *pool) {
    if (!pool) return;
    if (pool->free_event) CloseHandle(pool->free_event);
    free(pool->blocks);
    memset(pool, 0, sizeof(*pool));
}

/*
 * Acquire sets ownership and identity only. Frame, context, and action
 * storage is intentionally left as-is: ReadPackets fills the buffer,
 * packet_parse clears the context, and action constructors clear the action,
 * so each is written exactly once per pool cycle at the point of use.
 */
ndisapi_packet_block_t *ndisapi_packet_block_acquire(ndisapi_packet_pool_t *pool,
                                                     HANDLE adapter_handle,
                                                     DWORD adapter_index) {
    ndisapi_packet_block_t *block = NULL;

    if (!pool) return NULL;

    AcquireSRWLockExclusive(&pool->lock);
    if (pool->free_list) {
        block = pool->free_list;
        pool->free_list = block->next;
        pool->free_count--;
        block->next = NULL;
        block->ref_count = 1;
    }
    ReleaseSRWLockExclusive(&pool->lock);

    if (!block) return NULL;

    block->adapter_handle = adapter_handle;
    block->adapter_index = adapter_index;
    block->direction = 0;
    block->buffer.m_hAdapter = adapter_handle;

    return block;
}

ndisapi_packet_block_t *ndisapi_packet_block_acquire_or_flush(ndisapi_engine_t *engine,
                                                             HANDLE adapter_handle,
                                                             DWORD adapter_index,
                                                             DWORD wait_ms) {
    ndisapi_packet_block_t *block;

    if (!engine) return NULL;

    block = ndisapi_packet_block_acquire(&engine->packet_pool,
                                         adapter_handle, adapter_index);
    if (!block && wait_ms > 0 && engine->packet_pool.free_event) {
        /* Arm the free event, re-check to avoid a lost wake, then wait. */
        ResetEvent(engine->packet_pool.free_event);
        block = ndisapi_packet_block_acquire(&engine->packet_pool,
                                             adapter_handle, adapter_index);
        if (!block) {
            WaitForSingleObject(engine->packet_pool.free_event, wait_ms);
            block = ndisapi_packet_block_acquire(&engine->packet_pool,
                                                 adapter_handle, adapter_index);
        }
    }
    if (block) return block;

    ndisapi_counter_inc(&engine->counters.pool_exhausted);
    ndisapi_counter_inc(&engine->counters.adapter_queue_flushes);
    ndisapi_count_overload_drop(engine);

    if (engine->driver_handle && engine->driver_handle != INVALID_HANDLE_VALUE &&
        adapter_handle) {
        if (!FlushAdapterPacketQueue(engine->driver_handle, adapter_handle)) {
            LOG_WARN("NDISAPI packet pool exhausted adapter=%p flush failed err=%lu",
                     adapter_handle, (unsigned long)GetLastError());
            return NULL;
        }
    }

    LOG_WARN("NDISAPI packet pool exhausted adapter=%p queue flushed",
             adapter_handle);
    return NULL;
}

void ndisapi_packet_block_retain(ndisapi_packet_block_t *block) {
    if (!block) return;
    InterlockedIncrement(&block->ref_count);
}

void ndisapi_packet_block_release(ndisapi_packet_block_t *block) {
    ndisapi_packet_pool_t *pool;
    LONG ref;

    if (!block) return;

    ref = InterlockedDecrement(&block->ref_count);
    if (ref > 0) return;
    if (ref < 0) {
        block->ref_count = 0;
        return;
    }

    pool = block->pool;
    if (!pool) return;

    AcquireSRWLockExclusive(&pool->lock);
    {
        int was_empty = (pool->free_count == 0);

        block->next = pool->free_list;
        pool->free_list = block;
        pool->free_count++;
        ReleaseSRWLockExclusive(&pool->lock);

        if (was_empty && pool->free_event) {
            SetEvent(pool->free_event);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Flow worker dispatch                                              */
/* ------------------------------------------------------------------ */

DWORD ndisapi_flow_worker_count_for_cpu(DWORD cpu_count) {
    if (cpu_count < NDISAPI_FLOW_WORKER_MIN) return NDISAPI_FLOW_WORKER_MIN;
    if (cpu_count > NDISAPI_FLOW_WORKER_MAX) return NDISAPI_FLOW_WORKER_MAX;
    return cpu_count;
}

static DWORD ndisapi_detect_cpu_count(void) {
    SYSTEM_INFO info;

    memset(&info, 0, sizeof(info));
    GetSystemInfo(&info);
    if (info.dwNumberOfProcessors == 0) return 1;
    return info.dwNumberOfProcessors;
}

static uint16_t ndisapi_read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t ndisapi_read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static uint64_t ndisapi_hash_mix(uint64_t hash, uint64_t value) {
    hash ^= value;
    hash *= 1099511628211ULL;
    return hash;
}

static uint32_t ndisapi_packet_direction(PINTERMEDIATE_BUFFER buf) {
    if (!buf) return 0;
    if (buf->m_dwDeviceFlags & PACKET_FLAG_ON_SEND) return 1;
    if (buf->m_dwDeviceFlags & PACKET_FLAG_ON_RECEIVE) return 2;
    return 0;
}

uint64_t ndisapi_packet_flow_hash(PINTERMEDIATE_BUFFER buf) {
    const uint8_t *frame;
    uint64_t hash = 1469598103934665603ULL;
    uint32_t adapter_bits;

    if (!buf) return hash;

    adapter_bits = (uint32_t)(uintptr_t)buf->m_hAdapter;
    hash = ndisapi_hash_mix(hash, adapter_bits);
    hash = ndisapi_hash_mix(hash, (uint64_t)((uintptr_t)buf->m_hAdapter >> 32));

    frame = buf->m_IBuffer;
    if (buf->m_Length >= ETHER_HDR_LEN + 20 &&
        frame[12] == 0x08 && frame[13] == 0x00) {
        const uint8_t *ip = frame + ETHER_HDR_LEN;
        uint8_t ihl = (uint8_t)((ip[0] & 0x0FU) * 4U);
        uint8_t proto = ip[9];

        if ((ip[0] >> 4) == 4 && ihl >= 20 &&
            buf->m_Length >= (DWORD)(ETHER_HDR_LEN + ihl + 4U) &&
            (proto == WTP_IPPROTO_TCP || proto == WTP_IPPROTO_UDP)) {
            const uint8_t *l4 = ip + ihl;
            uint32_t src_ip = ndisapi_read_be32(ip + 12);
            uint32_t dst_ip = ndisapi_read_be32(ip + 16);
            uint16_t src_port = ndisapi_read_be16(l4);
            uint16_t dst_port = ndisapi_read_be16(l4 + 2);
            uint32_t low_ip = src_ip;
            uint32_t high_ip = dst_ip;
            uint16_t low_port = src_port;
            uint16_t high_port = dst_port;

            if (src_ip > dst_ip ||
                (src_ip == dst_ip && src_port > dst_port)) {
                low_ip = dst_ip;
                high_ip = src_ip;
                low_port = dst_port;
                high_port = src_port;
            }

            hash = ndisapi_hash_mix(hash, proto);
            hash = ndisapi_hash_mix(hash, low_ip);
            hash = ndisapi_hash_mix(hash, low_port);
            hash = ndisapi_hash_mix(hash, high_ip);
            hash = ndisapi_hash_mix(hash, high_port);
            return hash;
        }
    }

    hash = ndisapi_hash_mix(hash, ndisapi_packet_direction(buf));
    return hash;
}

DWORD ndisapi_packet_worker_index(ndisapi_engine_t *engine,
                                  PINTERMEDIATE_BUFFER buf) {
    DWORD count;

    if (!engine || engine->flow_worker_count == 0) return 0;
    count = engine->flow_worker_count;
    return (DWORD)(ndisapi_packet_flow_hash(buf) % count);
}

/*
 * Enqueue up to `count` blocks into one worker under a single lock pass and
 * wake the worker once when anything landed. Returns the number enqueued.
 */
static DWORD ndisapi_flow_worker_enqueue_group(ndisapi_flow_worker_t *worker,
                                               ndisapi_packet_block_t **blocks,
                                               DWORD count) {
    DWORD enqueued = 0;

    if (!worker || !blocks || count == 0) return 0;

    AcquireSRWLockExclusive(&worker->lock);
    while (enqueued < count && worker->count < NDISAPI_FLOW_QUEUE_DEPTH) {
        worker->queue[worker->tail] = blocks[enqueued];
        worker->tail = (worker->tail + 1U) % NDISAPI_FLOW_QUEUE_DEPTH;
        worker->count++;
        enqueued++;
    }
    ReleaseSRWLockExclusive(&worker->lock);

    if (enqueued > 0 && worker->work_event) {
        SetEvent(worker->work_event);
    }
    return enqueued;
}

/*
 * Route a read batch to its flow workers: blocks are grouped by worker so
 * each worker pays one queue lock and one wake per read batch. Overflow on a
 * full queue keeps the bounded-wait-then-drop overload semantics per block.
 */
DWORD ndisapi_flow_worker_dispatch_batch(ndisapi_engine_t *engine,
                                         ndisapi_packet_block_t **blocks,
                                         DWORD count,
                                         DWORD wait_ms) {
    ndisapi_packet_block_t *group[NDISAPI_BATCH_SIZE];
    DWORD indexes[NDISAPI_BATCH_SIZE];
    DWORD dispatched = 0;
    DWORD offset = 0;

    if (!blocks || count == 0) return 0;

    if (!engine || engine->flow_worker_count == 0) {
        for (DWORD i = 0; i < count; i++) {
            ndisapi_packet_block_release(blocks[i]);
        }
        return 0;
    }

    while (offset < count) {
        ndisapi_packet_block_t **chunk_blocks = blocks + offset;
        DWORD chunk = count - offset;
        DWORD i, w;

        if (chunk > NDISAPI_BATCH_SIZE) chunk = NDISAPI_BATCH_SIZE;

        for (i = 0; i < chunk; i++) {
            ndisapi_packet_block_t *block = chunk_blocks[i];
            block->direction = block->buffer.m_dwDeviceFlags;
            indexes[i] = ndisapi_packet_worker_index(engine, &block->buffer);
        }

        for (w = 0; w < engine->flow_worker_count; w++) {
            ndisapi_flow_worker_t *worker = &engine->flow_workers[w];
            DWORD group_count = 0;
            DWORD enqueued;

            for (i = 0; i < chunk; i++) {
                if (indexes[i] == w) {
                    group[group_count++] = chunk_blocks[i];
                }
            }
            if (group_count == 0) continue;

            enqueued = ndisapi_flow_worker_enqueue_group(worker, group,
                                                         group_count);
            if (enqueued < group_count && wait_ms > 0 && worker->space_event) {
                /* Arm the space event, re-check, then wait once bounded. */
                ResetEvent(worker->space_event);
                enqueued += ndisapi_flow_worker_enqueue_group(
                    worker, group + enqueued, group_count - enqueued);
                if (enqueued < group_count) {
                    WaitForSingleObject(worker->space_event, wait_ms);
                    enqueued += ndisapi_flow_worker_enqueue_group(
                        worker, group + enqueued, group_count - enqueued);
                }
            }
            dispatched += enqueued;

            if (enqueued < group_count) {
                DWORD dropped = group_count - enqueued;

                LOG_WARN("NDISAPI flow worker queue full worker=%lu adapter=%p "
                         "dropped=%lu",
                         (unsigned long)w,
                         group[enqueued]->adapter_handle,
                         (unsigned long)dropped);
                for (i = enqueued; i < group_count; i++) {
                    ndisapi_counter_inc(&engine->counters.enqueue_timeouts);
                    ndisapi_count_overload_drop(engine);
                    ndisapi_packet_block_release(group[i]);
                }
            }
        }

        offset += chunk;
    }

    return dispatched;
}

int ndisapi_flow_worker_enqueue(ndisapi_engine_t *engine,
                                ndisapi_packet_block_t *block,
                                DWORD wait_ms) {
    if (!block) return 0;
    return ndisapi_flow_worker_dispatch_batch(engine, &block, 1, wait_ms) == 1;
}

static DWORD ndisapi_flow_worker_dequeue_many(ndisapi_flow_worker_t *worker,
                                              ndisapi_packet_block_t **blocks,
                                              DWORD max_count) {
    DWORD count = 0;
    int was_full;

    if (!worker || !blocks || max_count == 0) return 0;

    AcquireSRWLockExclusive(&worker->lock);
    was_full = (worker->count == NDISAPI_FLOW_QUEUE_DEPTH);
    while (worker->count > 0 && count < max_count) {
        blocks[count++] = worker->queue[worker->head];
        worker->queue[worker->head] = NULL;
        worker->head = (worker->head + 1U) % NDISAPI_FLOW_QUEUE_DEPTH;
        worker->count--;
    }
    ReleaseSRWLockExclusive(&worker->lock);

    if (was_full && count > 0 && worker->space_event) {
        SetEvent(worker->space_event);
    }

    return count;
}

/*
 * Drained-batch processing: plan every block, execute the whole set through
 * one executor call so driver-send handoff amortizes per drain, then release.
 */
static void ndisapi_process_packet_blocks(ndisapi_flow_worker_t *worker,
                                          ndisapi_packet_block_t **blocks,
                                          DWORD count) {
    ndisapi_engine_t *engine = worker ? worker->engine : NULL;
    traffic_action_t *actions[NDISAPI_BATCH_SIZE];
    DWORD action_count = 0;
    DWORD i;

    if (!blocks || count == 0) return;
    if (count > NDISAPI_BATCH_SIZE) count = NDISAPI_BATCH_SIZE;

    if (!engine) {
        for (i = 0; i < count; i++) {
            ndisapi_packet_block_release(blocks[i]);
        }
        return;
    }

    for (i = 0; i < count; i++) {
        ndisapi_packet_block_t *block = blocks[i];
        PINTERMEDIATE_BUFFER buf = block ? &block->buffer : NULL;

        if (!buf || buf->m_Length < ETHER_HDR_LEN) continue;

        if (!buf->m_hAdapter) {
            buf->m_hAdapter = block->adapter_handle;
        }
        block->adapter_handle = buf->m_hAdapter;
        block->direction = buf->m_dwDeviceFlags;

        if (packet_parse(&block->context, buf)) {
            traffic_plan_packet(engine,
                                packet_observe(&block->context),
                                &block->action);
        } else {
            traffic_action_pass_raw(&block->action,
                                    buf->m_IBuffer, buf->m_Length,
                                    buf, "unparseable");
        }
        block->action.owner_block = block;
        actions[action_count++] = &block->action;
    }

    if (action_count > 0) {
        traffic_execute_action_batch(engine, actions, action_count);
    }

    for (i = 0; i < count; i++) {
        ndisapi_packet_block_release(blocks[i]);
    }
}

static DWORD WINAPI ndisapi_flow_worker_proc(LPVOID param) {
    ndisapi_flow_worker_t *worker = (ndisapi_flow_worker_t *)param;
    ndisapi_engine_t *engine = worker ? worker->engine : NULL;
    ndisapi_packet_block_t *blocks[NDISAPI_BATCH_SIZE];
    DWORD count;

    if (!worker || !engine) return 0;

    for (;;) {
        count = ndisapi_flow_worker_dequeue_many(worker, blocks,
                                                 NDISAPI_BATCH_SIZE);
        if (count > 0) {
            ndisapi_process_packet_blocks(worker, blocks, count);
            continue;
        }

        if (!engine->running) break;

        WaitForSingleObject(worker->work_event, 100);
        ResetEvent(worker->work_event);
    }

    for (;;) {
        count = ndisapi_flow_worker_dequeue_many(worker, blocks,
                                                 NDISAPI_BATCH_SIZE);
        if (count == 0) break;
        ndisapi_process_packet_blocks(worker, blocks, count);
    }

    return 0;
}

static error_t ndisapi_start_flow_workers(ndisapi_engine_t *engine) {
    DWORD i;

    if (engine->flow_worker_count == 0) {
        engine->flow_worker_count =
            ndisapi_flow_worker_count_for_cpu(ndisapi_detect_cpu_count());
    }

    for (i = 0; i < engine->flow_worker_count; i++) {
        ndisapi_flow_worker_t *worker = &engine->flow_workers[i];
        memset(worker, 0, sizeof(*worker));
        worker->engine = engine;
        worker->worker_index = i;
        InitializeSRWLock(&worker->lock);
        worker->work_event = CreateEvent(NULL, TRUE, FALSE, NULL);
        worker->space_event = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!worker->work_event || !worker->space_event) {
            LOG_ERROR("CreateEvent for flow worker %lu failed: %lu",
                      (unsigned long)i, GetLastError());
            return ERR_GENERIC;
        }
        worker->thread = CreateThread(NULL, 0, ndisapi_flow_worker_proc,
                                      worker, 0, NULL);
        if (!worker->thread) {
            LOG_ERROR("Failed to create flow worker thread %lu",
                      (unsigned long)i);
            return ERR_GENERIC;
        }
    }

    LOG_INFO("Started %lu flow workers",
             (unsigned long)engine->flow_worker_count);
    return ERR_OK;
}

static void ndisapi_wake_flow_workers(ndisapi_engine_t *engine) {
    DWORD i;

    for (i = 0; i < engine->flow_worker_count; i++) {
        if (engine->flow_workers[i].work_event) {
            SetEvent(engine->flow_workers[i].work_event);
        }
    }
}

static void ndisapi_drain_flow_worker(ndisapi_flow_worker_t *worker) {
    ndisapi_packet_block_t *blocks[NDISAPI_BATCH_SIZE];
    DWORD count;
    DWORD i;

    for (;;) {
        count = ndisapi_flow_worker_dequeue_many(worker, blocks,
                                                 NDISAPI_BATCH_SIZE);
        if (count == 0) break;
        for (i = 0; i < count; i++) {
            ndisapi_packet_block_release(blocks[i]);
        }
    }
}

static void ndisapi_stop_flow_workers(ndisapi_engine_t *engine) {
    DWORD i;

    if (!engine) return;

    ndisapi_wake_flow_workers(engine);
    for (i = 0; i < engine->flow_worker_count; i++) {
        ndisapi_flow_worker_t *worker = &engine->flow_workers[i];
        if (worker->thread) {
            WaitForSingleObject(worker->thread, 5000);
            CloseHandle(worker->thread);
            worker->thread = NULL;
        }
        ndisapi_drain_flow_worker(worker);
        if (worker->work_event) {
            CloseHandle(worker->work_event);
            worker->work_event = NULL;
        }
        if (worker->space_event) {
            CloseHandle(worker->space_event);
            worker->space_event = NULL;
        }
    }
}

static const char *ndisapi_send_target_name(int to_adapter);
static int ndisapi_send_batch_grouped_with(ndisapi_engine_t *engine,
                                           PINTERMEDIATE_BUFFER *bufs,
                                           DWORD count,
                                           int to_adapter,
                                           PETH_M_REQUEST request,
                                           unsigned char *used);
static size_t ndisapi_m_request_size(DWORD packet_count);

/* ------------------------------------------------------------------ */
/*  Dedicated sender threads                                          */
/* ------------------------------------------------------------------ */

static ndisapi_sender_t *ndisapi_sender_for_target(ndisapi_engine_t *engine,
                                                   ndisapi_send_target_t target) {
    if (!engine || target < 0 || target >= NDISAPI_SENDER_COUNT) return NULL;
    return &engine->senders[target];
}

static int ndisapi_sender_target_is_adapter(ndisapi_send_target_t target) {
    return target == NDISAPI_SEND_TARGET_ADAPTER;
}

static void ndisapi_release_queued_send_item(ndisapi_send_item_t *item) {
    if (!item) return;
    if (item->block) {
        ndisapi_packet_block_release(item->block);
        item->block = NULL;
    }
    if (item->free_after_send && item->buf) {
        free(item->buf);
    }
    memset(item, 0, sizeof(*item));
}

/*
 * Batch handoff to a sender: one lock pass enqueues the whole chunk and one
 * wake signals the sender, so executor flushes do not pay per-packet
 * synchronization. Overflowing items are dropped with counters after the
 * lock is released.
 */
static int ndisapi_enqueue_send_batch(ndisapi_engine_t *engine,
                                      ndisapi_send_item_t *items,
                                      DWORD count,
                                      ndisapi_send_target_t target) {
    ndisapi_sender_t *sender = ndisapi_sender_for_target(engine, target);
    ndisapi_send_item_t overflow[NDISAPI_BATCH_SIZE];
    DWORD queued_total = 0;
    DWORD offset = 0;
    int all_ok = 1;

    if (!engine || !items || count == 0) return 1;

    while (offset < count) {
        DWORD chunk = count - offset;
        DWORD overflow_count = 0;
        DWORD i;

        if (chunk > NDISAPI_BATCH_SIZE) chunk = NDISAPI_BATCH_SIZE;

        if (sender) AcquireSRWLockExclusive(&sender->lock);
        for (i = 0; i < chunk; i++) {
            ndisapi_send_item_t queued = items[offset + i];

            if (!queued.buf && queued.block) {
                queued.buf = &queued.block->buffer;
            }
            if (!queued.buf) continue;

            if (queued.block) {
                ndisapi_packet_block_retain(queued.block);
            }

            if (sender && sender->count < NDISAPI_SENDER_QUEUE_DEPTH) {
                sender->queue[sender->tail] = queued;
                sender->tail = (sender->tail + 1U) % NDISAPI_SENDER_QUEUE_DEPTH;
                sender->count++;
                queued_total++;
            } else {
                overflow[overflow_count++] = queued;
            }
        }
        if (sender) ReleaseSRWLockExclusive(&sender->lock);

        for (i = 0; i < overflow_count; i++) {
            ndisapi_counter_inc(&engine->counters.send_failures);
            LOG_WARN("NDISAPI sender queue full target=%s adapter=%p",
                     ndisapi_send_target_name(ndisapi_sender_target_is_adapter(target)),
                     overflow[i].buf ? overflow[i].buf->m_hAdapter : NULL);
            ndisapi_release_queued_send_item(&overflow[i]);
            all_ok = 0;
        }

        offset += chunk;
    }

    if (queued_total > 0 && sender && sender->work_event) {
        SetEvent(sender->work_event);
    }

    return all_ok;
}

int ndisapi_enqueue_send_batch_to_mstcp(ndisapi_engine_t *engine,
                                        ndisapi_send_item_t *items,
                                        DWORD count) {
    return ndisapi_enqueue_send_batch(engine, items, count,
                                      NDISAPI_SEND_TARGET_MSTCP);
}

int ndisapi_enqueue_send_batch_to_adapter(ndisapi_engine_t *engine,
                                          ndisapi_send_item_t *items,
                                          DWORD count) {
    return ndisapi_enqueue_send_batch(engine, items, count,
                                      NDISAPI_SEND_TARGET_ADAPTER);
}

static DWORD ndisapi_sender_dequeue_many(ndisapi_sender_t *sender,
                                         ndisapi_send_item_t *items,
                                         DWORD max_count) {
    DWORD count = 0;

    if (!sender || !items || max_count == 0) return 0;

    AcquireSRWLockExclusive(&sender->lock);
    while (sender->count > 0 && count < max_count) {
        items[count] = sender->queue[sender->head];
        memset(&sender->queue[sender->head], 0,
               sizeof(sender->queue[sender->head]));
        sender->head = (sender->head + 1U) % NDISAPI_SENDER_QUEUE_DEPTH;
        sender->count--;
        count++;
    }
    ReleaseSRWLockExclusive(&sender->lock);

    return count;
}

static void ndisapi_sender_send_items(ndisapi_sender_t *sender,
                                      ndisapi_send_item_t *items,
                                      DWORD count) {
    PINTERMEDIATE_BUFFER bufs[NDISAPI_BATCH_SIZE];
    int to_adapter;
    DWORD i;

    if (!sender || !items || count == 0) return;

    for (i = 0; i < count; i++) {
        bufs[i] = items[i].buf;
    }

    to_adapter = ndisapi_sender_target_is_adapter(sender->target);
    if (sender->send_request && sender->group_scratch) {
        ndisapi_send_batch_grouped_with(sender->engine, bufs, count,
                                        to_adapter,
                                        sender->send_request,
                                        sender->group_scratch);
    } else if (to_adapter) {
        ndisapi_send_batch_to_adapter(sender->engine, bufs, count);
    } else {
        ndisapi_send_batch_to_mstcp(sender->engine, bufs, count);
    }

    for (i = 0; i < count; i++) {
        ndisapi_release_queued_send_item(&items[i]);
    }
}

static DWORD WINAPI ndisapi_sender_proc(LPVOID param) {
    ndisapi_sender_t *sender = (ndisapi_sender_t *)param;
    ndisapi_engine_t *engine = sender ? sender->engine : NULL;
    ndisapi_send_item_t items[NDISAPI_BATCH_SIZE];
    DWORD count;

    if (!sender || !engine) return 0;

    for (;;) {
        count = ndisapi_sender_dequeue_many(sender, items, NDISAPI_BATCH_SIZE);
        if (count > 0) {
            ndisapi_sender_send_items(sender, items, count);
            continue;
        }

        if (!engine->running) break;

        WaitForSingleObject(sender->work_event, 100);
        ResetEvent(sender->work_event);
    }

    for (;;) {
        count = ndisapi_sender_dequeue_many(sender, items, NDISAPI_BATCH_SIZE);
        if (count == 0) break;
        ndisapi_sender_send_items(sender, items, count);
    }

    return 0;
}

static error_t ndisapi_start_senders(ndisapi_engine_t *engine) {
    DWORD i;

    for (i = 0; i < NDISAPI_SENDER_COUNT; i++) {
        ndisapi_sender_t *sender = &engine->senders[i];
        memset(sender, 0, sizeof(*sender));
        sender->engine = engine;
        sender->target = (ndisapi_send_target_t)i;
        InitializeSRWLock(&sender->lock);
        sender->send_request =
            (PETH_M_REQUEST)calloc(1, ndisapi_m_request_size(NDISAPI_BATCH_SIZE));
        sender->group_scratch =
            (unsigned char *)calloc(NDISAPI_BATCH_SIZE,
                                    sizeof(*sender->group_scratch));
        if (!sender->send_request || !sender->group_scratch) {
            LOG_ERROR("Failed to allocate sender %lu flush storage",
                      (unsigned long)i);
            return ERR_MEMORY;
        }
        sender->work_event = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!sender->work_event) {
            LOG_ERROR("CreateEvent for sender %lu failed: %lu",
                      (unsigned long)i, GetLastError());
            return ERR_GENERIC;
        }
        sender->thread = CreateThread(NULL, 0, ndisapi_sender_proc,
                                      sender, 0, NULL);
        if (!sender->thread) {
            LOG_ERROR("Failed to create sender thread %lu",
                      (unsigned long)i);
            return ERR_GENERIC;
        }
    }

    LOG_INFO("Started %d sender threads", NDISAPI_SENDER_COUNT);
    return ERR_OK;
}

static void ndisapi_wake_senders(ndisapi_engine_t *engine) {
    DWORD i;

    if (!engine) return;
    for (i = 0; i < NDISAPI_SENDER_COUNT; i++) {
        if (engine->senders[i].work_event) {
            SetEvent(engine->senders[i].work_event);
        }
    }
}

static void ndisapi_drain_sender(ndisapi_sender_t *sender) {
    ndisapi_send_item_t items[NDISAPI_BATCH_SIZE];
    DWORD count;

    for (;;) {
        count = ndisapi_sender_dequeue_many(sender, items, NDISAPI_BATCH_SIZE);
        if (count == 0) break;
        for (DWORD i = 0; i < count; i++) {
            ndisapi_release_queued_send_item(&items[i]);
        }
    }
}

static void ndisapi_stop_senders(ndisapi_engine_t *engine) {
    DWORD i;

    if (!engine) return;

    ndisapi_wake_senders(engine);
    for (i = 0; i < NDISAPI_SENDER_COUNT; i++) {
        ndisapi_sender_t *sender = &engine->senders[i];
        if (sender->thread) {
            WaitForSingleObject(sender->thread, 5000);
            CloseHandle(sender->thread);
            sender->thread = NULL;
        }
        ndisapi_drain_sender(sender);
        if (sender->work_event) {
            CloseHandle(sender->work_event);
            sender->work_event = NULL;
        }
        free(sender->send_request);
        sender->send_request = NULL;
        free(sender->group_scratch);
        sender->group_scratch = NULL;
    }
}

static size_t ndisapi_m_request_size(DWORD packet_count) {
    if (packet_count == 0) packet_count = 1;
    return sizeof(ETH_M_REQUEST) +
        ((size_t)packet_count - 1U) * sizeof(NDISRD_ETH_Packet);
}

static const char *ndisapi_send_target_name(int to_adapter) {
    return to_adapter ? "ADAPTER" : "MSTCP";
}

static int ndisapi_send_request(ndisapi_engine_t *engine,
                                PETH_M_REQUEST request,
                                int to_adapter) {
    BOOL ok;
    DWORD sent;
    DWORD failed;
    const char *target = ndisapi_send_target_name(to_adapter);

    request->dwPacketsSuccess = 0;
    ok = to_adapter
        ? SendPacketsToAdapter(engine->driver_handle, request)
        : SendPacketsToMstcp(engine->driver_handle, request);

    if (!ok) {
        ndisapi_counter_add(&engine->counters.send_failures,
                            (LONG64)request->dwPacketsNumber);
        LOG_WARN("NDISAPI send failed target=%s adapter=%p packets=%lu err=%lu",
                 target, request->hAdapterHandle,
                 (unsigned long)request->dwPacketsNumber,
                 (unsigned long)GetLastError());
        return 0;
    }

    sent = request->dwPacketsSuccess;
    if (sent > request->dwPacketsNumber) sent = request->dwPacketsNumber;
    ndisapi_counter_add(&engine->counters.packets_sent, (LONG64)sent);

    if (sent == request->dwPacketsNumber) {
        return 1;
    }

    failed = request->dwPacketsNumber - sent;
    ndisapi_counter_add(&engine->counters.send_failures, (LONG64)failed);
    LOG_WARN("NDISAPI partial send target=%s adapter=%p sent=%lu/%lu",
             target, request->hAdapterHandle,
             (unsigned long)sent,
             (unsigned long)request->dwPacketsNumber);
    return 0;
}

static int ndisapi_send_batch_grouped_with(ndisapi_engine_t *engine,
                                           PINTERMEDIATE_BUFFER *bufs,
                                           DWORD count,
                                           int to_adapter,
                                           PETH_M_REQUEST request,
                                           unsigned char *used) {
    int all_ok = 1;
    DWORD i;

    if (!engine || !bufs || count == 0) return 1;
    if (!request || !used) return 0;

    memset(used, 0, (size_t)count);

    for (i = 0; i < count; i++) {
        HANDLE adapter;
        DWORD group_count = 0;
        DWORD j;

        if (used[i]) continue;
        used[i] = 1;

        if (!bufs[i]) {
            ndisapi_counter_add(&engine->counters.send_failures, 1);
            LOG_WARN("NDISAPI send skipped null packet target=%s",
                     ndisapi_send_target_name(to_adapter));
            all_ok = 0;
            continue;
        }

        adapter = bufs[i]->m_hAdapter;
        if (!adapter) {
            ndisapi_counter_add(&engine->counters.send_failures, 1);
            LOG_WARN("NDISAPI send skipped packet without adapter target=%s",
                     ndisapi_send_target_name(to_adapter));
            all_ok = 0;
            continue;
        }

        request->hAdapterHandle = adapter;
        request->EthPacket[group_count++].Buffer = bufs[i];

        for (j = i + 1; j < count; j++) {
            if (used[j] || !bufs[j] || bufs[j]->m_hAdapter != adapter) {
                continue;
            }
            used[j] = 1;
            request->EthPacket[group_count++].Buffer = bufs[j];
        }

        request->dwPacketsNumber = group_count;
        if (!ndisapi_send_request(engine, request, to_adapter)) {
            all_ok = 0;
        }
    }

    return all_ok;
}

static int ndisapi_send_batch_grouped(ndisapi_engine_t *engine,
                                      PINTERMEDIATE_BUFFER *bufs,
                                      DWORD count,
                                      int to_adapter) {
    PETH_M_REQUEST request;
    unsigned char *used;
    int all_ok;

    if (!engine || !bufs || count == 0) return 1;

    request = (PETH_M_REQUEST)calloc(1, ndisapi_m_request_size(count));
    used = (unsigned char *)calloc((size_t)count, sizeof(*used));
    if (!request || !used) {
        free(request);
        free(used);
        ndisapi_counter_add(&engine->counters.send_failures, (LONG64)count);
        LOG_WARN("NDISAPI send allocation failed target=%s packets=%lu",
                 ndisapi_send_target_name(to_adapter), (unsigned long)count);
        return 0;
    }

    all_ok = ndisapi_send_batch_grouped_with(engine, bufs, count, to_adapter,
                                             request, used);

    free(used);
    free(request);
    return all_ok;
}

int ndisapi_send_batch_to_mstcp(ndisapi_engine_t *engine,
                                PINTERMEDIATE_BUFFER *bufs,
                                DWORD count) {
    return ndisapi_send_batch_grouped(engine, bufs, count, 0);
}

int ndisapi_send_batch_to_adapter(ndisapi_engine_t *engine,
                                  PINTERMEDIATE_BUFFER *bufs,
                                  DWORD count) {
    return ndisapi_send_batch_grouped(engine, bufs, count, 1);
}

int ndisapi_send_to_mstcp(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf) {
    return ndisapi_send_batch_to_mstcp(engine, &buf, 1);
}

int ndisapi_send_to_adapter(ndisapi_engine_t *engine, PINTERMEDIATE_BUFFER buf) {
    return ndisapi_send_batch_to_adapter(engine, &buf, 1);
}

/* ------------------------------------------------------------------ */
/*  Adapter enumeration                                               */
/* ------------------------------------------------------------------ */

static error_t ndisapi_enumerate_adapters(ndisapi_engine_t *engine) {
    TCP_AdapterList ad_list;

    memset(&ad_list, 0, sizeof(ad_list));

    if (!GetTcpipBoundAdaptersInfo(engine->driver_handle, &ad_list)) {
        LOG_ERROR("GetTcpipBoundAdaptersInfo failed: err=%lu", GetLastError());
        return ERR_NETWORK;
    }

    if (ad_list.m_nAdapterCount == 0) {
        LOG_ERROR("No network adapters found");
        return ERR_NOT_FOUND;
    }

    engine->adapter_count = ad_list.m_nAdapterCount;
    if (engine->adapter_count > NDISAPI_MAX_ADAPTERS) {
        LOG_WARN("Truncating adapter list from %lu to %d",
                 (unsigned long)engine->adapter_count, NDISAPI_MAX_ADAPTERS);
        engine->adapter_count = NDISAPI_MAX_ADAPTERS;
    }

    for (DWORD i = 0; i < engine->adapter_count; i++) {
        engine->adapter_handles[i] = ad_list.m_nAdapterHandle[i];
        memcpy(engine->adapter_mac[i], ad_list.m_czCurrentAddress[i], 6);

        /* Convert internal name to friendly name */
        ConvertWindows2000AdapterName(
            (LPCSTR)ad_list.m_szAdapterNameList[i],
            engine->adapter_names[i],
            sizeof(engine->adapter_names[i]));

        LOG_INFO("Adapter %lu: %s (MAC=%02X:%02X:%02X:%02X:%02X:%02X, MTU=%u)",
                 (unsigned long)i,
                 engine->adapter_names[i],
                 engine->adapter_mac[i][0], engine->adapter_mac[i][1],
                 engine->adapter_mac[i][2], engine->adapter_mac[i][3],
                 engine->adapter_mac[i][4], engine->adapter_mac[i][5],
                 ad_list.m_usMTU[i]);
    }

    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/*  Adapter mode / event setup                                        */
/* ------------------------------------------------------------------ */

static error_t ndisapi_setup_adapters(ndisapi_engine_t *engine) {
    for (DWORD i = 0; i < engine->adapter_count; i++) {
        ADAPTER_MODE mode;
        ndisapi_adapter_reader_t *reader = &engine->readers[i];

        /* Set packet event so the driver signals us when packets arrive */
        if (!SetPacketEvent(engine->driver_handle,
                            engine->adapter_handles[i],
                            reader->packet_event)) {
            LOG_ERROR("SetPacketEvent failed for adapter %lu: err=%lu",
                      (unsigned long)i, GetLastError());
            return ERR_GENERIC;
        }

        /* Tunnel mode: intercept packets in both directions */
        memset(&mode, 0, sizeof(mode));
        mode.hAdapterHandle = engine->adapter_handles[i];
        mode.dwFlags = MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL;

        if (!SetAdapterMode(engine->driver_handle, &mode)) {
            LOG_ERROR("SetAdapterMode failed for adapter %lu: err=%lu",
                      (unsigned long)i, GetLastError());
            return ERR_GENERIC;
        }
    }

    return ERR_OK;
}

/* ------------------------------------------------------------------ */
/*  Adapter-list change detection                                     */
/* ------------------------------------------------------------------ */

static void ndisapi_mark_adapter_restart_required(ndisapi_engine_t *engine) {
    if (!engine || engine->adapter_restart_required) return;

    engine->adapter_restart_required = 1;
    ndisapi_counter_inc(&engine->counters.adapter_restart_required);
    LOG_WARN("NDISAPI adapter list changed; restart required");
}

static DWORD WINAPI ndisapi_adapter_monitor_proc(LPVOID param) {
    ndisapi_engine_t *engine = (ndisapi_engine_t *)param;

    if (!engine || !engine->adapter_change_event) return 0;

    while (engine->running && !engine->adapter_restart_required) {
        DWORD wait_result = WaitForSingleObject(engine->adapter_change_event, 1000);
        if (wait_result == WAIT_OBJECT_0) {
            ResetEvent(engine->adapter_change_event);
            if (engine->running) {
                ndisapi_mark_adapter_restart_required(engine);
            }
            break;
        }
    }

    return 0;
}

static error_t ndisapi_start_adapter_monitor(ndisapi_engine_t *engine) {
    if (!engine) return ERR_PARAM;

    engine->adapter_change_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!engine->adapter_change_event) {
        LOG_ERROR("CreateEvent for adapter-list changes failed: %lu",
                  GetLastError());
        return ERR_GENERIC;
    }

    if (!SetAdapterListChangeEvent(engine->driver_handle,
                                   engine->adapter_change_event)) {
        LOG_ERROR("SetAdapterListChangeEvent failed: err=%lu", GetLastError());
        return ERR_GENERIC;
    }

    engine->adapter_monitor_thread =
        CreateThread(NULL, 0, ndisapi_adapter_monitor_proc, engine, 0, NULL);
    if (!engine->adapter_monitor_thread) {
        LOG_ERROR("Failed to create adapter-list monitor thread");
        return ERR_GENERIC;
    }

    return ERR_OK;
}

static void ndisapi_stop_adapter_monitor(ndisapi_engine_t *engine) {
    if (!engine) return;

    if (engine->adapter_change_event) {
        SetEvent(engine->adapter_change_event);
    }
    if (engine->adapter_monitor_thread) {
        WaitForSingleObject(engine->adapter_monitor_thread, 5000);
        CloseHandle(engine->adapter_monitor_thread);
        engine->adapter_monitor_thread = NULL;
    }
    if (engine->driver_handle && engine->driver_handle != INVALID_HANDLE_VALUE) {
        SetAdapterListChangeEvent(engine->driver_handle, NULL);
    }
    if (engine->adapter_change_event) {
        CloseHandle(engine->adapter_change_event);
        engine->adapter_change_event = NULL;
    }
}

/* ------------------------------------------------------------------ */
/*  Adapter reader allocation                                         */
/* ------------------------------------------------------------------ */

static int ndisapi_alloc_packet_pool(ndisapi_engine_t *engine) {
    DWORD pool_capacity;

    if (!engine || engine->adapter_count == 0 ||
        engine->flow_worker_count == 0) {
        return 0;
    }

    pool_capacity = ndisapi_packet_pool_capacity_for(engine->adapter_count,
                                                     engine->flow_worker_count);
    if (!ndisapi_packet_pool_init(&engine->packet_pool, pool_capacity)) {
        LOG_ERROR("Failed to allocate packet block pool (%lu blocks)",
                  (unsigned long)pool_capacity);
        return 0;
    }

    LOG_INFO("Allocated packet block pool: %lu blocks (%lu KB) = "
             "readers %lux%dx2 + workers %lux%d + senders %dx%d",
             (unsigned long)pool_capacity,
             (unsigned long)((size_t)pool_capacity *
                             sizeof(ndisapi_packet_block_t) / 1024U),
             (unsigned long)engine->adapter_count, NDISAPI_BATCH_SIZE,
             (unsigned long)engine->flow_worker_count, NDISAPI_FLOW_QUEUE_DEPTH,
             NDISAPI_SENDER_COUNT, NDISAPI_SENDER_QUEUE_DEPTH);
    return 1;
}

static int ndisapi_alloc_readers(ndisapi_engine_t *engine) {
    DWORD i;

    for (i = 0; i < engine->adapter_count; i++) {
        ndisapi_adapter_reader_t *reader = &engine->readers[i];
        size_t request_size = ndisapi_m_request_size(NDISAPI_BATCH_SIZE);

        memset(reader, 0, sizeof(*reader));
        reader->engine = engine;
        reader->adapter_index = i;
        reader->adapter_handle = engine->adapter_handles[i];

        reader->packet_event = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!reader->packet_event) {
            LOG_ERROR("CreateEvent for adapter %lu failed: %lu",
                      (unsigned long)i, GetLastError());
            return 0;
        }

        reader->read_request = (PETH_M_REQUEST)calloc(1, request_size);
        if (!reader->read_request) {
            LOG_ERROR("Failed to allocate reader buffers for adapter %lu",
                      (unsigned long)i);
            return 0;
        }

        reader->read_request->hAdapterHandle = reader->adapter_handle;
        reader->read_request->dwPacketsNumber = NDISAPI_BATCH_SIZE;
    }

    LOG_INFO("Allocated %lu adapter reader requests",
             (unsigned long)engine->adapter_count);
    return 1;
}

static void ndisapi_free_readers(ndisapi_engine_t *engine) {
    for (DWORD i = 0; i < engine->adapter_count; i++) {
        ndisapi_adapter_reader_t *reader = &engine->readers[i];
        free(reader->read_request);
        reader->read_request = NULL;
    }
}

/* ------------------------------------------------------------------ */
/*  Adapter reader thread                                             */
/* ------------------------------------------------------------------ */

/*
 * Reads from one adapter-associated queue until it is drained (a partial
 * batch), dispatching each read batch to the flow workers in per-worker
 * groups, then re-waits on the adapter packet event.
 */
static DWORD WINAPI ndisapi_reader_proc(LPVOID param) {
    ndisapi_adapter_reader_t *reader = (ndisapi_adapter_reader_t *)param;
    ndisapi_engine_t *engine = reader ? reader->engine : NULL;
    DWORD batch  = (DWORD)NDISAPI_BATCH_SIZE;
    DWORD packets_read, acquired, j;
    ndisapi_packet_block_t *blocks[NDISAPI_BATCH_SIZE];

    if (!reader || !engine || !reader->read_request) return 0;

    while (engine->running) {
        /* Wait for packets */
        WaitForSingleObject(reader->packet_event, 100);
        ResetEvent(reader->packet_event);

        if (!engine->running) break;

        /* Drain the adapter queue: keep reading while full batches return. */
        for (;;) {
            acquired = 0;
            for (j = 0; j < batch; j++) {
                ndisapi_packet_block_t *block =
                    ndisapi_packet_block_acquire_or_flush(engine,
                                                          reader->adapter_handle,
                                                          reader->adapter_index,
                                                          NDISAPI_PACKET_POOL_WAIT_MS);
                if (!block) break;
                blocks[acquired] = block;
                reader->read_request->EthPacket[acquired].Buffer = &block->buffer;
                acquired++;
            }
            if (acquired == 0) break;

            /* Read into pool-owned blocks. */
            reader->read_request->dwPacketsSuccess = 0;
            reader->read_request->dwPacketsNumber = acquired;
            if (!ReadPackets(engine->driver_handle, reader->read_request)) {
                for (j = 0; j < acquired; j++) {
                    ndisapi_packet_block_release(blocks[j]);
                }
                break;
            }

            packets_read = reader->read_request->dwPacketsSuccess;
            if (packets_read > acquired) packets_read = acquired;
            for (j = packets_read; j < acquired; j++) {
                ndisapi_packet_block_release(blocks[j]);
            }
            if (packets_read == 0) break;

            InterlockedAdd64(&engine->counters.packets_recv,
                             (LONG64)packets_read);

            for (j = 0; j < packets_read; j++) {
                ndisapi_packet_block_t *block = blocks[j];

                block->buffer.m_hAdapter = reader->adapter_handle;
                block->adapter_handle = reader->adapter_handle;
                block->adapter_index = reader->adapter_index;
            }
            ndisapi_flow_worker_dispatch_batch(engine, blocks, packets_read,
                                               NDISAPI_FLOW_ENQUEUE_WAIT_MS);

            if (packets_read < acquired) break;
            if (!engine->running) break;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Engine lifecycle                                                  */
/* ------------------------------------------------------------------ */

static void ndisapi_close_driver(ndisapi_engine_t *engine) {
    if (engine->driver_handle && engine->driver_handle != INVALID_HANDLE_VALUE) {
        /* Remove packet events and reset modes on all adapters */
        if (engine->adapter_count > 0) {
            for (DWORD i = 0; i < engine->adapter_count; i++) {
                ADAPTER_MODE mode;
                ndisapi_adapter_reader_t *reader = &engine->readers[i];
                memset(&mode, 0, sizeof(mode));
                mode.hAdapterHandle = engine->adapter_handles[i];
                mode.dwFlags = 0;
                SetAdapterMode(engine->driver_handle, &mode);
                SetPacketEvent(engine->driver_handle,
                               engine->adapter_handles[i], NULL);
                if (reader->packet_event) {
                    CloseHandle(reader->packet_event);
                    reader->packet_event = NULL;
                }
            }
        }

        CloseFilterDriver(engine->driver_handle);
    }
    engine->driver_handle = INVALID_HANDLE_VALUE;
}

static void ndisapi_close_udp_socket(ndisapi_engine_t *engine) {
    if (engine->udp_fwd_sock != INVALID_SOCKET) {
        closesocket(engine->udp_fwd_sock);
    }
    engine->udp_fwd_sock = INVALID_SOCKET;
}

static void ndisapi_wake_readers(ndisapi_engine_t *engine) {
    for (DWORD i = 0; i < engine->adapter_count; i++) {
        if (engine->readers[i].packet_event) {
            SetEvent(engine->readers[i].packet_event);
        }
    }
}

static void ndisapi_join_readers(ndisapi_engine_t *engine) {
    for (DWORD i = 0; i < engine->adapter_count; i++) {
        if (engine->readers[i].thread) {
            WaitForSingleObject(engine->readers[i].thread, 5000);
            CloseHandle(engine->readers[i].thread);
            engine->readers[i].thread = NULL;
        }
    }
}

static error_t ndisapi_start_fail(ndisapi_engine_t *engine,
                                  dns_hijack_t *dns_hijack,
                                  int dns_forwarder_started,
                                  error_t err) {
    engine->running = 0;
    ndisapi_wake_readers(engine);
    if (dns_forwarder_started) {
        dns_hijack_shutdown(dns_hijack);
    }
    ndisapi_join_readers(engine);
    ndisapi_stop_adapter_monitor(engine);
    ndisapi_stop_flow_workers(engine);
    ndisapi_stop_senders(engine);
    ndisapi_close_driver(engine);
    ndisapi_close_udp_socket(engine);
    ndisapi_free_readers(engine);
    ndisapi_packet_pool_destroy(&engine->packet_pool);
    return err;
}

error_t ndisapi_start(ndisapi_engine_t *engine, app_config_t *config,
                      conntrack_t *conntrack, proc_lookup_t *proc_lookup,
                      dns_hijack_t *dns_hijack,
                      uint16_t tcp_relay_port, uint16_t udp_relay_port) {
    int dns_forwarder_started = 0;
    error_t err;

    memset(engine, 0, sizeof(*engine));
    engine->driver_handle = INVALID_HANDLE_VALUE;
    engine->config = config;
    engine->conntrack = conntrack;
    engine->proc_lookup = proc_lookup;
    engine->dns_hijack = dns_hijack;
    engine->tcp_relay_port = tcp_relay_port;
    engine->udp_relay_port = udp_relay_port;
    engine->running = 1;
    engine->udp_fwd_sock = INVALID_SOCKET;

    /* 1. Open the driver.  OpenFilterDriver returns a CNdisApi* cast to HANDLE;
     * it never returns NULL (new always succeeds).  Check IsDriverLoaded(). */
    engine->driver_handle = OpenFilterDriver(L"NDISRD");
    if (!engine->driver_handle) {
        LOG_ERROR("OpenFilterDriver returned NULL");
        engine->running = 0;
        return ERR_PERMISSION;
    }
    if (!IsDriverLoaded(engine->driver_handle)) {
        DWORD err_code = GetLastError();
        LOG_ERROR("WinpkFilter driver not loaded: err=%lu", err_code);
        if (err_code == 2) {
            LOG_ERROR("ndisrd.sys driver not found — install WinpkFilter driver");
        } else if (err_code == 5) {
            LOG_ERROR("Access denied — is the WinpkFilter driver installed?");
        }
        engine->running = 0;
        return ERR_PERMISSION;
    }

    {
        DWORD ver = GetDriverVersion(engine->driver_handle);
        LOG_INFO("WinpkFilter driver version %lu.%lu.%lu",
                 (unsigned long)((ver >> 24) & 0xFF),
                 (unsigned long)((ver >> 16) & 0xFF),
                 (unsigned long)(ver & 0xFFFF));
    }

    /* 2. Enumerate adapters */
    err = ndisapi_enumerate_adapters(engine);
    if (err != ERR_OK) {
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, err);
    }

    /* 3. Size the pipeline: worker count feeds the pool capacity model, and
     * the driver-side pool covers the reader in-flight component. */
    engine->flow_worker_count =
        ndisapi_flow_worker_count_for_cpu(ndisapi_detect_cpu_count());
    {
        DWORD driver_pool = engine->adapter_count * (DWORD)NDISAPI_BATCH_SIZE * 2;
        SetPoolSize(driver_pool);
        LOG_INFO("ndisapi buffer pool size set to %lu (reader in-flight)",
                 (unsigned long)driver_pool);
    }

    /* 4. Allocate caller-owned packet blocks */
    if (!ndisapi_alloc_packet_pool(engine)) {
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_MEMORY);
    }

    /* 5. Allocate per-adapter reader requests/events */
    if (!ndisapi_alloc_readers(engine)) {
        LOG_ERROR("Failed to allocate ndisapi adapter readers");
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_MEMORY);
    }

    /* 6. Set adapter modes and per-adapter events */
    err = ndisapi_setup_adapters(engine);
    if (err != ERR_OK) {
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, err);
    }

    /* 7. Create UDP forwarding socket (for UDP relay) */
    engine->udp_fwd_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (engine->udp_fwd_sock == INVALID_SOCKET) {
        LOG_ERROR("UDP fwd socket: socket() failed: %d", WSAGetLastError());
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_NETWORK);
    }
    {
        struct sockaddr_in bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind_addr.sin_port = 0;
        if (bind(engine->udp_fwd_sock, (struct sockaddr *)&bind_addr,
                 sizeof(bind_addr)) == SOCKET_ERROR) {
            LOG_ERROR("UDP fwd socket: bind() failed: %d", WSAGetLastError());
            return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_NETWORK);
        }
        struct sockaddr_in local;
        int local_len = sizeof(local);
        if (getsockname(engine->udp_fwd_sock, (struct sockaddr *)&local,
                        &local_len) == SOCKET_ERROR) {
            LOG_ERROR("UDP fwd socket: getsockname() failed: %d", WSAGetLastError());
            return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_NETWORK);
        }
        LOG_INFO("UDP forwarding socket bound to 127.0.0.1:%u", ntohs(local.sin_port));
    }

    /* 8. Start DNS forwarder if loopback DNS is configured */
    if (dns_hijack->use_socket_fwd) {
        if (dns_hijack_start_forwarder(dns_hijack, engine) != ERR_OK) {
            LOG_ERROR("Failed to start DNS forwarder");
            return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_GENERIC);
        }
        dns_forwarder_started = 1;
    }

    /* 9. Watch adapter-list changes; phase 1 logs restart-required only */
    err = ndisapi_start_adapter_monitor(engine);
    if (err != ERR_OK) {
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, err);
    }

    /* 10. Start dedicated senders before flow workers can enqueue sends */
    err = ndisapi_start_senders(engine);
    if (err != ERR_OK) {
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, err);
    }

    /* 11. Start flow workers before adapter readers produce packet blocks */
    err = ndisapi_start_flow_workers(engine);
    if (err != ERR_OK) {
        return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, err);
    }

    /* 12. Spawn one reader thread per adapter */
    for (DWORD i = 0; i < engine->adapter_count; i++) {
        engine->readers[i].thread = CreateThread(NULL, 0, ndisapi_reader_proc,
                                                 &engine->readers[i], 0, NULL);
        if (!engine->readers[i].thread) {
            LOG_ERROR("Failed to create ndisapi reader thread %lu",
                      (unsigned long)i);
            return ndisapi_start_fail(engine, dns_hijack, dns_forwarder_started, ERR_GENERIC);
        }
    }

    LOG_INFO("ndisapi engine started with %lu adapter readers",
             (unsigned long)engine->adapter_count);
    return ERR_OK;
}

void ndisapi_stop(ndisapi_engine_t *engine) {
    engine->running = 0;

    /* Signal packet events so blocked readers wake up */
    ndisapi_wake_readers(engine);

    /* Shutdown DNS forwarder */
    if (engine->dns_hijack && engine->dns_hijack->use_socket_fwd) {
        dns_hijack_shutdown(engine->dns_hijack);
    }

    /* Join readers */
    ndisapi_join_readers(engine);

    /* Stop adapter-list monitor */
    ndisapi_stop_adapter_monitor(engine);

    /* Drain flow workers after readers stop producing */
    ndisapi_stop_flow_workers(engine);

    /* Drain senders after workers stop producing send work */
    ndisapi_stop_senders(engine);

    /* Close driver (resets adapter modes) */
    ndisapi_close_driver(engine);

    /* Free reader buffers */
    ndisapi_free_readers(engine);

    /* Free packet blocks */
    ndisapi_packet_pool_destroy(&engine->packet_pool);

    /* Close UDP socket */
    ndisapi_close_udp_socket(engine);

    LOG_INFO("ndisapi engine stopped");
}

void ndisapi_snapshot_counters(ndisapi_engine_t *engine, ndisapi_counters_t *out) {
    memset(out, 0, sizeof(*out));
    out->packets_recv   = InterlockedExchange64(&engine->counters.packets_recv, 0);
    out->packets_sent   = InterlockedExchange64(&engine->counters.packets_sent, 0);
    out->packets_dropped= InterlockedExchange64(&engine->counters.packets_dropped, 0);
    out->send_failures  = InterlockedExchange64(&engine->counters.send_failures, 0);
    out->udp_forwarded  = InterlockedExchange64(&engine->counters.udp_forwarded, 0);
    out->pool_exhausted = InterlockedExchange64(&engine->counters.pool_exhausted, 0);
    out->adapter_queue_flushes =
        InterlockedExchange64(&engine->counters.adapter_queue_flushes, 0);
    out->overload_drops =
        InterlockedExchange64(&engine->counters.overload_drops, 0);
    out->enqueue_timeouts =
        InterlockedExchange64(&engine->counters.enqueue_timeouts, 0);
    out->adapter_restart_required =
        InterlockedExchange64(&engine->counters.adapter_restart_required, 0);
}
