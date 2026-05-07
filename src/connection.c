#include "connection.h"
#include "log.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

static uint64_t get_tick_ms(void) {
    return GetTickCount64();
}

static unsigned int bucket_index_full(conntrack_t *ct, uint32_t src_ip, uint16_t src_port,
                                      uint32_t dst_ip, uint16_t dst_port, uint8_t protocol) {
    uint32_t x = src_ip ^ dst_ip ^
                 ((uint32_t)src_port << 16) ^ (uint32_t)dst_port ^
                 ((uint32_t)protocol * 0x9E3779B1U);
    x ^= x >> 16;
    x *= 0x7FEB352DU;
    x ^= x >> 15;
    return x % (unsigned int)ct->bucket_count;
}

static int conntrack_key_matches(const conntrack_entry_t *e, uint32_t src_ip, uint16_t src_port,
                                 uint32_t dst_ip, uint16_t dst_port, uint8_t protocol) {
    return e->key_src_ip == src_ip &&
           e->src_port == src_port &&
           e->key_dst_ip == dst_ip &&
           e->key_dst_port == dst_port &&
           e->protocol == protocol;
}

static conntrack_entry_t *pool_alloc(conntrack_t *ct) {
    conntrack_entry_t *e;
    AcquireSRWLockExclusive(&ct->pool_lock);
    e = ct->free_list;
    if (e) {
        ct->free_list = e->next;
        memset(e, 0, sizeof(*e));
    }
    ReleaseSRWLockExclusive(&ct->pool_lock);
    return e;
}

static void pool_free(conntrack_t *ct, conntrack_entry_t *e) {
    AcquireSRWLockExclusive(&ct->pool_lock);
    memset(e, 0, sizeof(*e));
    e->next = ct->free_list;
    ct->free_list = e;
    ReleaseSRWLockExclusive(&ct->pool_lock);
}

static void counter_inc(volatile LONG64 *counter) {
    InterlockedIncrement64(counter);
}

static void remove_stale_bucket(conntrack_t *ct, int i, uint64_t now, int *removed) {
    conntrack_entry_t **pp = &ct->buckets[i];
    while (*pp) {
        if ((now - (*pp)->timestamp) > (CONNTRACK_TTL_SEC * 1000ULL)) {
            conntrack_entry_t *old = *pp;
            *pp = old->next;
            pool_free(ct, old);
            (*removed)++;
        } else {
            pp = &(*pp)->next;
        }
    }
}

static DWORD WINAPI cleanup_thread_proc(LPVOID param) {
    conntrack_t *ct = (conntrack_t *)param;
    DWORD wait_ms = CONNTRACK_CLEANUP_INTERVAL_SEC * 1000U;

    while (ct->running) {
        DWORD wait = WaitForSingleObject(ct->stop_event, wait_ms);
        if (wait == WAIT_OBJECT_0 || !ct->running) break;

        uint64_t now = get_tick_ms();
        int removed = 0;

        for (size_t i = 0; i < ct->bucket_count; i++) {
            AcquireSRWLockExclusive(&ct->locks[i]);
            remove_stale_bucket(ct, (int)i, now, &removed);
            ReleaseSRWLockExclusive(&ct->locks[i]);
        }

        if (removed > 0) {
            InterlockedAdd64(&ct->counters.stale_cleanups, removed);
            LOG_DEBUG("Conntrack cleanup: removed %d stale entries", removed);
        }
    }
    return 0;
}

error_t conntrack_init(conntrack_t *ct) {
    memset(ct, 0, sizeof(*ct));
    ct->bucket_count = CONNTRACK_BUCKETS;
    ct->pool_size = CONNTRACK_POOL_SIZE;
    ct->buckets = (conntrack_entry_t **)calloc(ct->bucket_count, sizeof(ct->buckets[0]));
    ct->locks = (SRWLOCK *)calloc(ct->bucket_count, sizeof(ct->locks[0]));
    ct->pool = (conntrack_entry_t *)calloc(ct->pool_size, sizeof(ct->pool[0]));
    if (!ct->buckets || !ct->locks || !ct->pool) {
        LOG_ERROR("Failed to allocate conntrack tables");
        free(ct->buckets);
        free(ct->locks);
        free(ct->pool);
        memset(ct, 0, sizeof(*ct));
        return ERR_MEMORY;
    }
    for (size_t i = 0; i < ct->bucket_count; i++) {
        InitializeSRWLock(&ct->locks[i]);
    }
    InitializeSRWLock(&ct->pool_lock);

    for (size_t i = 0; i < ct->pool_size; i++) {
        ct->pool[i].next = ct->free_list;
        ct->free_list = &ct->pool[i];
    }

    ct->stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ct->stop_event) {
        LOG_ERROR("Failed to create conntrack cleanup stop event");
        free(ct->buckets);
        free(ct->locks);
        free(ct->pool);
        memset(ct, 0, sizeof(*ct));
        return ERR_GENERIC;
    }

    ct->running = 1;
    ct->cleanup_thread = CreateThread(NULL, 0, cleanup_thread_proc, ct, 0, NULL);
    if (!ct->cleanup_thread) {
        LOG_ERROR("Failed to create conntrack cleanup thread");
        ct->running = 0;
        CloseHandle(ct->stop_event);
        ct->stop_event = NULL;
        free(ct->buckets);
        free(ct->locks);
        free(ct->pool);
        memset(ct, 0, sizeof(*ct));
        return ERR_GENERIC;
    }
    return ERR_OK;
}

void conntrack_shutdown(conntrack_t *ct) {
    ct->running = 0;
    if (ct->stop_event) SetEvent(ct->stop_event);
    if (ct->cleanup_thread) {
        WaitForSingleObject(ct->cleanup_thread, 5000);
        CloseHandle(ct->cleanup_thread);
        ct->cleanup_thread = NULL;
    }

    for (size_t i = 0; i < ct->bucket_count; i++) {
        AcquireSRWLockExclusive(&ct->locks[i]);
        ct->buckets[i] = NULL;
        ReleaseSRWLockExclusive(&ct->locks[i]);
    }

    AcquireSRWLockExclusive(&ct->pool_lock);
    ct->free_list = NULL;
    for (size_t i = 0; i < ct->pool_size; i++) {
        ct->pool[i].next = ct->free_list;
        ct->free_list = &ct->pool[i];
    }
    ReleaseSRWLockExclusive(&ct->pool_lock);

    if (ct->stop_event) {
        CloseHandle(ct->stop_event);
        ct->stop_event = NULL;
    }

    free(ct->buckets);
    free(ct->locks);
    free(ct->pool);
    memset(ct, 0, sizeof(*ct));
}

error_t conntrack_add_key(conntrack_t *ct, uint32_t key_src_ip, uint16_t src_port,
                          uint32_t client_ip, uint32_t orig_dst_ip, uint16_t orig_dst_port,
                          uint8_t protocol, uint32_t pid, const char *process_name,
                          uint32_t if_idx, uint32_t sub_if_idx) {
    return conntrack_add_key_full(ct, key_src_ip, src_port, 0, 0, client_ip, src_port,
                                  orig_dst_ip, orig_dst_port, protocol, pid, process_name,
                                  if_idx, sub_if_idx, src_port);
}

error_t conntrack_add_key_full(conntrack_t *ct, uint32_t key_src_ip, uint16_t key_src_port,
                               uint32_t key_dst_ip, uint16_t key_dst_port,
                               uint32_t client_ip, uint16_t client_port,
                               uint32_t orig_dst_ip, uint16_t orig_dst_port,
                               uint8_t protocol, uint32_t pid, const char *process_name,
                               uint32_t if_idx, uint32_t sub_if_idx,
                               uint16_t relay_src_port) {
    unsigned int idx = bucket_index_full(ct, key_src_ip, key_src_port, key_dst_ip, key_dst_port, protocol);

    AcquireSRWLockExclusive(&ct->locks[idx]);

    conntrack_entry_t *e = ct->buckets[idx];
    while (e) {
        if (conntrack_key_matches(e, key_src_ip, key_src_port, key_dst_ip, key_dst_port, protocol)) {
            e->key_src_ip = key_src_ip;
            e->key_dst_ip = key_dst_ip;
            e->key_dst_port = key_dst_port;
            e->client_port = client_port;
            if (e->relay_src_port == 0) {
                e->relay_src_port = relay_src_port;
            }
            e->src_ip = client_ip;
            e->orig_dst_ip = orig_dst_ip;
            e->orig_dst_port = orig_dst_port;
            e->pid = pid;
            if (process_name) safe_str_copy(e->process_name, sizeof(e->process_name), process_name);
            e->timestamp = get_tick_ms();
            e->if_idx = if_idx;
            e->sub_if_idx = sub_if_idx;
            ReleaseSRWLockExclusive(&ct->locks[idx]);
            counter_inc(&ct->counters.updates);
            return ERR_OK;
        }
        e = e->next;
    }

    e = pool_alloc(ct);
    if (!e) {
        ReleaseSRWLockExclusive(&ct->locks[idx]);
        counter_inc(&ct->counters.pool_exhausted);
        LOG_WARN("Conntrack pool exhausted; dropping flow metadata");
        return ERR_BUSY;
    }

    e->src_port = key_src_port;
    e->key_src_ip = key_src_ip;
    e->key_dst_ip = key_dst_ip;
    e->key_dst_port = key_dst_port;
    e->client_port = client_port;
    e->relay_src_port = relay_src_port;
    e->src_ip = client_ip;
    e->orig_dst_ip = orig_dst_ip;
    e->orig_dst_port = orig_dst_port;
    e->protocol = protocol;
    e->pid = pid;
    if (process_name) safe_str_copy(e->process_name, sizeof(e->process_name), process_name);
    e->timestamp = get_tick_ms();
    e->if_idx = if_idx;
    e->sub_if_idx = sub_if_idx;
    e->next = ct->buckets[idx];
    ct->buckets[idx] = e;

    ReleaseSRWLockExclusive(&ct->locks[idx]);
    counter_inc(&ct->counters.adds);
    return ERR_OK;
}

error_t conntrack_add(conntrack_t *ct, uint16_t src_port, uint32_t src_ip,
                     uint32_t orig_dst_ip, uint16_t orig_dst_port, uint8_t protocol,
                     uint32_t pid, const char *process_name,
                     uint32_t if_idx, uint32_t sub_if_idx) {
    return conntrack_add_key_full(ct, src_ip, src_port, 0, 0, src_ip, src_port,
                                  orig_dst_ip, orig_dst_port, protocol, pid, process_name,
                                  if_idx, sub_if_idx, src_port);
}

error_t conntrack_get(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol,
                      uint32_t *orig_dst_ip, uint16_t *orig_dst_port) {
    conntrack_entry_t entry;
    error_t err = conntrack_get_full(ct, src_ip, src_port, protocol, &entry);
    if (err != ERR_OK) return err;
    if (orig_dst_ip) *orig_dst_ip = entry.orig_dst_ip;
    if (orig_dst_port) *orig_dst_port = entry.orig_dst_port;
    return ERR_OK;
}

error_t conntrack_get_full(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol,
                           conntrack_entry_t *out) {
    return conntrack_get_full_key(ct, src_ip, src_port, 0, 0, protocol, out);
}

error_t conntrack_get_full_key(conntrack_t *ct, uint32_t src_ip, uint16_t src_port,
                               uint32_t dst_ip, uint16_t dst_port, uint8_t protocol,
                               conntrack_entry_t *out) {
    unsigned int idx = bucket_index_full(ct, src_ip, src_port, dst_ip, dst_port, protocol);

    AcquireSRWLockShared(&ct->locks[idx]);

    conntrack_entry_t *e = ct->buckets[idx];
    while (e) {
        if (conntrack_key_matches(e, src_ip, src_port, dst_ip, dst_port, protocol)) {
            memcpy(out, e, sizeof(*out));
            out->next = NULL;
            ReleaseSRWLockShared(&ct->locks[idx]);
            return ERR_OK;
        }
        e = e->next;
    }

    ReleaseSRWLockShared(&ct->locks[idx]);
    counter_inc(&ct->counters.misses);
    return ERR_NOT_FOUND;
}

void conntrack_remove(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol) {
    conntrack_remove_key(ct, src_ip, src_port, 0, 0, protocol);
}

void conntrack_remove_key(conntrack_t *ct, uint32_t src_ip, uint16_t src_port,
                          uint32_t dst_ip, uint16_t dst_port, uint8_t protocol) {
    unsigned int idx = bucket_index_full(ct, src_ip, src_port, dst_ip, dst_port, protocol);

    AcquireSRWLockExclusive(&ct->locks[idx]);

    conntrack_entry_t **pp = &ct->buckets[idx];
    while (*pp) {
        if (conntrack_key_matches(*pp, src_ip, src_port, dst_ip, dst_port, protocol)) {
            conntrack_entry_t *old = *pp;
            *pp = old->next;
            pool_free(ct, old);
            ReleaseSRWLockExclusive(&ct->locks[idx]);
            counter_inc(&ct->counters.removes);
            return;
        }
        pp = &(*pp)->next;
    }

    ReleaseSRWLockExclusive(&ct->locks[idx]);
}

void conntrack_touch(conntrack_t *ct, uint32_t src_ip, uint16_t src_port, uint8_t protocol) {
    conntrack_touch_key(ct, src_ip, src_port, 0, 0, protocol);
}

void conntrack_touch_key(conntrack_t *ct, uint32_t src_ip, uint16_t src_port,
                         uint32_t dst_ip, uint16_t dst_port, uint8_t protocol) {
    unsigned int idx = bucket_index_full(ct, src_ip, src_port, dst_ip, dst_port, protocol);

    AcquireSRWLockExclusive(&ct->locks[idx]);

    conntrack_entry_t *e = ct->buckets[idx];
    while (e) {
        if (conntrack_key_matches(e, src_ip, src_port, dst_ip, dst_port, protocol)) {
            e->timestamp = get_tick_ms();
            break;
        }
        e = e->next;
    }

    ReleaseSRWLockExclusive(&ct->locks[idx]);
}

void conntrack_snapshot_counters(conntrack_t *ct, conntrack_counters_t *out) {
    memset(out, 0, sizeof(*out));
    out->adds = InterlockedExchange64(&ct->counters.adds, 0);
    out->updates = InterlockedExchange64(&ct->counters.updates, 0);
    out->removes = InterlockedExchange64(&ct->counters.removes, 0);
    out->misses = InterlockedExchange64(&ct->counters.misses, 0);
    out->pool_exhausted = InterlockedExchange64(&ct->counters.pool_exhausted, 0);
    out->stale_cleanups = InterlockedExchange64(&ct->counters.stale_cleanups, 0);
}
