#include "connection.h"
#include "log.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

static uint64_t get_tick_ms(void) {
    return GetTickCount64();
}

static unsigned int bucket_index(uint16_t src_port, uint8_t protocol) {
    return (src_port ^ ((uint32_t)protocol << 8)) % CONNTRACK_BUCKETS;
}

static DWORD WINAPI cleanup_thread_proc(LPVOID param) {
    conntrack_t *ct = (conntrack_t *)param;
    while (ct->running) {
        Sleep(CONNTRACK_CLEANUP_INTERVAL_SEC * 1000);
        if (!ct->running) break;

        uint64_t now = get_tick_ms();
        int removed = 0;

        for (int i = 0; i < CONNTRACK_BUCKETS; i++) {
            AcquireSRWLockExclusive(&ct->locks[i]);
            conntrack_entry_t **pp = &ct->buckets[i];
            while (*pp) {
                if ((now - (*pp)->timestamp) > (CONNTRACK_TTL_SEC * 1000ULL)) {
                    conntrack_entry_t *old = *pp;
                    *pp = old->next;
                    free(old);
                    removed++;
                } else {
                    pp = &(*pp)->next;
                }
            }
            ReleaseSRWLockExclusive(&ct->locks[i]);
        }

        if (removed > 0) {
            LOG_DEBUG("Conntrack cleanup: removed %d stale entries", removed);
        }
    }
    return 0;
}

error_t conntrack_init(conntrack_t *ct) {
    memset(ct, 0, sizeof(*ct));
    for (int i = 0; i < CONNTRACK_BUCKETS; i++) {
        ct->buckets[i] = NULL;
        InitializeSRWLock(&ct->locks[i]);
    }
    ct->running = 1;
    ct->cleanup_thread = CreateThread(NULL, 0, cleanup_thread_proc, ct, 0, NULL);
    if (!ct->cleanup_thread) {
        LOG_ERROR("Failed to create conntrack cleanup thread");
        ct->running = 0;
        return ERR_GENERIC;
    }
    return ERR_OK;
}

void conntrack_shutdown(conntrack_t *ct) {
    ct->running = 0;
    if (ct->cleanup_thread) {
        WaitForSingleObject(ct->cleanup_thread, 5000);
        CloseHandle(ct->cleanup_thread);
        ct->cleanup_thread = NULL;
    }

    for (int i = 0; i < CONNTRACK_BUCKETS; i++) {
        conntrack_entry_t *e = ct->buckets[i];
        while (e) {
            conntrack_entry_t *next = e->next;
            free(e);
            e = next;
        }
        ct->buckets[i] = NULL;
    }
}

error_t conntrack_add(conntrack_t *ct, uint16_t src_port, uint32_t src_ip,
                     uint32_t orig_dst_ip, uint16_t orig_dst_port, uint8_t protocol,
                     uint32_t pid, const char *process_name,
                     uint32_t if_idx, uint32_t sub_if_idx) {
    unsigned int idx = bucket_index(src_port, protocol);

    AcquireSRWLockExclusive(&ct->locks[idx]);

    conntrack_entry_t *e = ct->buckets[idx];
    while (e) {
        if (e->src_port == src_port && e->protocol == protocol) {
            e->src_ip = src_ip;
            e->orig_dst_ip = orig_dst_ip;
            e->orig_dst_port = orig_dst_port;
            e->pid = pid;
            if (process_name) safe_str_copy(e->process_name, sizeof(e->process_name), process_name);
            e->timestamp = get_tick_ms();
            e->if_idx = if_idx;
            e->sub_if_idx = sub_if_idx;
            ReleaseSRWLockExclusive(&ct->locks[idx]);
            return ERR_OK;
        }
        e = e->next;
    }

    e = (conntrack_entry_t *)calloc(1, sizeof(conntrack_entry_t));
    if (!e) {
        ReleaseSRWLockExclusive(&ct->locks[idx]);
        return ERR_MEMORY;
    }

    e->src_port = src_port;
    e->src_ip = src_ip;
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
    return ERR_OK;
}

error_t conntrack_get(conntrack_t *ct, uint16_t src_port, uint8_t protocol,
                      uint32_t *orig_dst_ip, uint16_t *orig_dst_port) {
    unsigned int idx = bucket_index(src_port, protocol);

    AcquireSRWLockShared(&ct->locks[idx]);

    conntrack_entry_t *e = ct->buckets[idx];
    while (e) {
        if (e->src_port == src_port && e->protocol == protocol) {
            if (orig_dst_ip) *orig_dst_ip = e->orig_dst_ip;
            if (orig_dst_port) *orig_dst_port = e->orig_dst_port;
            ReleaseSRWLockShared(&ct->locks[idx]);
            return ERR_OK;
        }
        e = e->next;
    }

    ReleaseSRWLockShared(&ct->locks[idx]);
    return ERR_NOT_FOUND;
}

error_t conntrack_get_full(conntrack_t *ct, uint16_t src_port, uint8_t protocol,
                           conntrack_entry_t *out) {
    unsigned int idx = bucket_index(src_port, protocol);

    AcquireSRWLockShared(&ct->locks[idx]);

    conntrack_entry_t *e = ct->buckets[idx];
    while (e) {
        if (e->src_port == src_port && e->protocol == protocol) {
            memcpy(out, e, sizeof(*out));
            out->next = NULL;
            ReleaseSRWLockShared(&ct->locks[idx]);
            return ERR_OK;
        }
        e = e->next;
    }

    ReleaseSRWLockShared(&ct->locks[idx]);
    return ERR_NOT_FOUND;
}

void conntrack_remove(conntrack_t *ct, uint16_t src_port, uint8_t protocol) {
    unsigned int idx = bucket_index(src_port, protocol);

    AcquireSRWLockExclusive(&ct->locks[idx]);

    conntrack_entry_t **pp = &ct->buckets[idx];
    while (*pp) {
        if ((*pp)->src_port == src_port && (*pp)->protocol == protocol) {
            conntrack_entry_t *old = *pp;
            *pp = old->next;
            free(old);
            ReleaseSRWLockExclusive(&ct->locks[idx]);
            return;
        }
        pp = &(*pp)->next;
    }

    ReleaseSRWLockExclusive(&ct->locks[idx]);
}

void conntrack_touch(conntrack_t *ct, uint16_t src_port, uint8_t protocol) {
    unsigned int idx = bucket_index(src_port, protocol);

    AcquireSRWLockExclusive(&ct->locks[idx]);

    conntrack_entry_t *e = ct->buckets[idx];
    while (e) {
        if (e->src_port == src_port && e->protocol == protocol) {
            e->timestamp = get_tick_ms();
            break;
        }
        e = e->next;
    }

    ReleaseSRWLockExclusive(&ct->locks[idx]);
}
