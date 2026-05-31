#include "process/lookup.h"
#include "app/log.h"
#include "core/util.h"
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <winsock2.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>

/* ndisapi: no WFP flow events available; owner-table polling only */

static uint64_t tick_ms(void) {
    return GetTickCount64();
}

static unsigned int flow_hash(uint32_t ip, uint16_t port, uint8_t protocol) {
    uint32_t x = ip ^ ((uint32_t)port << 16) ^ ((uint32_t)protocol * 0x9E3779B1U);
    x ^= x >> 16;
    x *= 0x7FEB352DU;
    x ^= x >> 15;
    return x % PROC_FLOW_BUCKETS;
}

static unsigned int pid_hash(uint32_t pid) {
    uint32_t x = pid;
    x ^= x >> 16;
    x *= 0x7FEB352DU;
    x ^= x >> 15;
    return x % PROC_PID_BUCKETS;
}

static void counter_inc(volatile LONG64 *counter) {
    InterlockedIncrement64(counter);
}

static void put_unknown(char *name, int name_len) {
    if (name && name_len > 0) safe_str_copy(name, (size_t)name_len, "unknown");
}

/* Primary: CreateToolhelp32Snapshot works for all processes including
 * SYSTEM-level, no permission issues unlike OpenProcess. */
static int get_process_name_slow(uint32_t pid, char *name, int name_len) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    int found = 0;

    if (pid == 0 || !name || name_len <= 0) return 0;
    if (snap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                if (WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                        name, name_len, NULL, NULL) > 0)
                    found = 1;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static int pid_cache_get(proc_lookup_t *pl, uint32_t pid, char *name, int name_len) {
    unsigned int idx = pid_hash(pid);
    uint64_t now = tick_ms();

    AcquireSRWLockShared(&pl->pid_lock);
    for (proc_pid_entry_t *e = pl->pid_buckets[idx]; e; e = e->next) {
        if (e->pid == pid && (now - e->timestamp) < PROC_CACHE_TTL_MS) {
            if (name && name_len > 0) safe_str_copy(name, (size_t)name_len, e->name);
            ReleaseSRWLockShared(&pl->pid_lock);
            counter_inc(&pl->counters.pid_hits);
            return 1;
        }
    }
    ReleaseSRWLockShared(&pl->pid_lock);
    counter_inc(&pl->counters.pid_misses);
    return 0;
}

static proc_pid_entry_t *pid_cache_alloc_locked(proc_lookup_t *pl) {
    proc_pid_entry_t *oldest = NULL;

    if (pl->pid_used < pl->pid_pool_size) {
        return &pl->pid_pool[pl->pid_used++];
    }

    for (size_t i = 0; i < pl->pid_pool_size; i++) {
        if (!oldest || pl->pid_pool[i].timestamp < oldest->timestamp) {
            oldest = &pl->pid_pool[i];
        }
    }
    if (oldest) {
        unsigned int idx = pid_hash(oldest->pid);
        proc_pid_entry_t **pp = &pl->pid_buckets[idx];
        while (*pp) {
            if (*pp == oldest) {
                *pp = oldest->next;
                break;
            }
            pp = &(*pp)->next;
        }
    }
    return oldest;
}

static void pid_cache_put(proc_lookup_t *pl, uint32_t pid, const char *name) {
    unsigned int idx = pid_hash(pid);

    AcquireSRWLockExclusive(&pl->pid_lock);
    for (proc_pid_entry_t *e = pl->pid_buckets[idx]; e; e = e->next) {
        if (e->pid == pid) {
            safe_str_copy(e->name, sizeof(e->name), name ? name : "unknown");
            e->timestamp = tick_ms();
            ReleaseSRWLockExclusive(&pl->pid_lock);
            return;
        }
    }

    proc_pid_entry_t *e = pid_cache_alloc_locked(pl);
    if (e) {
        memset(e, 0, sizeof(*e));
        e->pid = pid;
        safe_str_copy(e->name, sizeof(e->name), name ? name : "unknown");
        e->timestamp = tick_ms();
        e->next = pl->pid_buckets[idx];
        pl->pid_buckets[idx] = e;
    }
    ReleaseSRWLockExclusive(&pl->pid_lock);
}

static void proc_name_for_pid(proc_lookup_t *pl, uint32_t pid, char *name, int name_len) {
    if (pid == 0) {
        put_unknown(name, name_len);
        return;
    }

    if (pid_cache_get(pl, pid, name, name_len)) {
        return;
    }

    if (!get_process_name_slow(pid, name, name_len)) {
        put_unknown(name, name_len);
    }
    pid_cache_put(pl, pid, name);
}

static void append_record(proc_lookup_t *pl, size_t *count, uint32_t ip,
                          uint16_t port, uint8_t protocol, uint32_t pid) {
    proc_flow_record_t *r;
    if (*count >= pl->flow_pool_size || port == 0) return;

    r = &pl->scratch[*count];
    memset(r, 0, sizeof(*r));
    r->ip = ip;
    r->port = port;
    r->protocol = protocol;
    r->pid = pid;
    (*count)++;
}

static void collect_tcp_flows(proc_lookup_t *pl, size_t *count) {
    PMIB_TCPTABLE_OWNER_PID table = NULL;
    DWORD size = 0;
    DWORD ret = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    if (ret != ERROR_INSUFFICIENT_BUFFER || size == 0) return;
    table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!table) return;

    ret = GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (ret == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *row = &table->table[i];
            uint16_t port = (uint16_t)ntohs((u_short)row->dwLocalPort);
            append_record(pl, count, row->dwLocalAddr, port, WTP_IPPROTO_TCP, row->dwOwningPid);
        }
    }

    free(table);
}

static void collect_udp_flows(proc_lookup_t *pl, size_t *count) {
    PMIB_UDPTABLE_OWNER_PID table = NULL;
    DWORD size = 0;
    DWORD ret = GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);

    if (ret != ERROR_INSUFFICIENT_BUFFER || size == 0) return;
    table = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
    if (!table) return;

    ret = GetExtendedUdpTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (ret == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID *row = &table->table[i];
            uint16_t port = (uint16_t)ntohs((u_short)row->dwLocalPort);
            append_record(pl, count, row->dwLocalAddr, port, WTP_IPPROTO_UDP, row->dwOwningPid);
        }
    }

    free(table);
}

static void flow_insert_locked(proc_lookup_t *pl, const proc_flow_record_t *r) {
    proc_flow_entry_t *e;
    unsigned int idx;

    if (pl->flow_used >= pl->flow_pool_size) {
        counter_inc(&pl->counters.pool_exhausted);
        return;
    }

    e = &pl->flow_pool[pl->flow_used++];
    memset(e, 0, sizeof(*e));
    e->ip = r->ip;
    e->port = r->port;
    e->protocol = r->protocol;
    e->pid = r->pid;
    safe_str_copy(e->name, sizeof(e->name), r->name[0] ? r->name : "unknown");

    idx = flow_hash(e->ip, e->port, e->protocol);
    e->next = pl->flow_buckets[idx];
    pl->flow_buckets[idx] = e;
}

static void proc_lookup_refresh_locked(proc_lookup_t *pl) {
    size_t count = 0;

    /*
     * Lock ordering: refresh_lock → flow_lock → pid_lock.
     * Caller holds refresh_lock; this function acquires flow_lock.
     * proc_name_for_pid may acquire pid_lock internally.
     */

    collect_tcp_flows(pl, &count);
    collect_udp_flows(pl, &count);

    for (size_t i = 0; i < count; i++) {
        proc_name_for_pid(pl, pl->scratch[i].pid, pl->scratch[i].name, sizeof(pl->scratch[i].name));
    }

    AcquireSRWLockExclusive(&pl->flow_lock);
    memset(pl->flow_buckets, 0, pl->flow_bucket_count * sizeof(pl->flow_buckets[0]));
    pl->flow_used = 0;
    for (size_t i = 0; i < count; i++) {
        flow_insert_locked(pl, &pl->scratch[i]);
    }
    pl->indexed_flows = pl->flow_used;
    pl->last_refresh_ms = tick_ms();
    counter_inc(&pl->counters.refreshes);
    ReleaseSRWLockExclusive(&pl->flow_lock);
}

static int proc_lookup_refresh_if_stale(proc_lookup_t *pl, uint64_t min_age_ms) {
    int refreshed = 0;
    uint64_t now;

    EnterCriticalSection(&pl->refresh_lock);
    now = tick_ms();
    if (min_age_ms == 0 || pl->last_refresh_ms == 0 ||
        now - pl->last_refresh_ms >= min_age_ms) {
        proc_lookup_refresh_locked(pl);
        refreshed = 1;
    }
    LeaveCriticalSection(&pl->refresh_lock);
    return refreshed;
}

static void proc_lookup_refresh(proc_lookup_t *pl) {
    (void)proc_lookup_refresh_if_stale(pl, 0);
}

static DWORD WINAPI refresh_thread_proc(LPVOID param) {
    proc_lookup_t *pl = (proc_lookup_t *)param;

    while (pl->running) {
        DWORD wait = WaitForSingleObject(pl->refresh_event, PROC_INDEX_REFRESH_MS);
        if (!pl->running) break;
        if (wait == WAIT_OBJECT_0) ResetEvent(pl->refresh_event);
        proc_lookup_refresh(pl);
    }

    return 0;
}

error_t proc_lookup_init(proc_lookup_t *pl) {
    memset(pl, 0, sizeof(*pl));
    pl->flow_bucket_count = PROC_FLOW_BUCKETS;
    pl->flow_pool_size = PROC_FLOW_POOL_SIZE;
    pl->pid_bucket_count = PROC_PID_BUCKETS;
    pl->pid_pool_size = PROC_PID_POOL_SIZE;
    pl->flow_buckets = (proc_flow_entry_t **)calloc(pl->flow_bucket_count, sizeof(pl->flow_buckets[0]));
    pl->flow_pool = (proc_flow_entry_t *)calloc(pl->flow_pool_size, sizeof(pl->flow_pool[0]));
    pl->pid_buckets = (proc_pid_entry_t **)calloc(pl->pid_bucket_count, sizeof(pl->pid_buckets[0]));
    pl->pid_pool = (proc_pid_entry_t *)calloc(pl->pid_pool_size, sizeof(pl->pid_pool[0]));
    pl->scratch = (proc_flow_record_t *)calloc(pl->flow_pool_size, sizeof(pl->scratch[0]));
    if (!pl->flow_buckets || !pl->flow_pool || !pl->pid_buckets || !pl->pid_pool || !pl->scratch) {
        LOG_ERROR("Failed to allocate process lookup tables");
        free(pl->flow_buckets);
        free(pl->flow_pool);
        free(pl->pid_buckets);
        free(pl->pid_pool);
        free(pl->scratch);
        memset(pl, 0, sizeof(*pl));
        return ERR_MEMORY;
    }
    InitializeSRWLock(&pl->flow_lock);
    InitializeSRWLock(&pl->pid_lock);
    InitializeCriticalSection(&pl->refresh_lock);
    pl->refresh_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!pl->refresh_event) {
        DeleteCriticalSection(&pl->refresh_lock);
        free(pl->flow_buckets);
        free(pl->flow_pool);
        free(pl->pid_buckets);
        free(pl->pid_pool);
        free(pl->scratch);
        memset(pl, 0, sizeof(*pl));
        return ERR_GENERIC;
    }
    pl->self_pid = GetCurrentProcessId();
    pl->running = 1;

    proc_lookup_refresh(pl);

    LOG_INFO("Process flow watcher not available (ndisapi); owner-table refresh only");

    pl->refresh_thread = CreateThread(NULL, 0, refresh_thread_proc, pl, 0, NULL);
    if (!pl->refresh_thread) {
        pl->running = 0;
        if (pl->refresh_event) CloseHandle(pl->refresh_event);
        DeleteCriticalSection(&pl->refresh_lock);
        free(pl->flow_buckets);
        free(pl->flow_pool);
        free(pl->pid_buckets);
        free(pl->pid_pool);
        free(pl->scratch);
        memset(pl, 0, sizeof(*pl));
        LOG_ERROR("Failed to create process index refresh thread");
        return ERR_GENERIC;
    }

    LOG_INFO("Process flow index initialized with %u flows", (unsigned int)pl->indexed_flows);
    return ERR_OK;
}

void proc_lookup_shutdown(proc_lookup_t *pl) {
    pl->running = 0;
    /* ndisapi: no flow handle or flow thread to close */
    if (pl->refresh_thread) {
        if (pl->refresh_event) SetEvent(pl->refresh_event);
        WaitForSingleObject(pl->refresh_thread, INFINITE);
        CloseHandle(pl->refresh_thread);
        pl->refresh_thread = NULL;
    }

    AcquireSRWLockExclusive(&pl->flow_lock);
    memset(pl->flow_buckets, 0, pl->flow_bucket_count * sizeof(pl->flow_buckets[0]));
    pl->flow_used = 0;
    pl->indexed_flows = 0;
    ReleaseSRWLockExclusive(&pl->flow_lock);

    AcquireSRWLockExclusive(&pl->pid_lock);
    memset(pl->pid_buckets, 0, pl->pid_bucket_count * sizeof(pl->pid_buckets[0]));
    pl->pid_used = 0;
    ReleaseSRWLockExclusive(&pl->pid_lock);

    if (pl->refresh_event) {
        CloseHandle(pl->refresh_event);
        pl->refresh_event = NULL;
    }
    DeleteCriticalSection(&pl->refresh_lock);
    free(pl->flow_buckets);
    free(pl->flow_pool);
    free(pl->pid_buckets);
    free(pl->pid_pool);
    free(pl->scratch);
    memset(pl, 0, sizeof(*pl));
}

static uint32_t proc_lookup_flow_cached(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port,
                                        uint8_t protocol, char *name_out, int name_len) {
    uint32_t pid = 0;
    unsigned int idx = flow_hash(src_ip, src_port, protocol);

    AcquireSRWLockShared(&pl->flow_lock);
    for (proc_flow_entry_t *e = pl->flow_buckets[idx]; e; e = e->next) {
        if (e->ip == src_ip && e->port == src_port && e->protocol == protocol) {
            pid = e->pid;
            if (name_out && name_len > 0) safe_str_copy(name_out, (size_t)name_len, e->name);
            counter_inc(&pl->counters.flow_hits);
            break;
        }
    }

    if (pid == 0) {
        idx = flow_hash(0, src_port, protocol);
        for (proc_flow_entry_t *e = pl->flow_buckets[idx]; e; e = e->next) {
            if (e->ip == 0 && e->port == src_port && e->protocol == protocol) {
                pid = e->pid;
                if (name_out && name_len > 0) safe_str_copy(name_out, (size_t)name_len, e->name);
                counter_inc(&pl->counters.wildcard_hits);
                break;
            }
        }
    }
    ReleaseSRWLockShared(&pl->flow_lock);

    return pid;
}

static uint32_t proc_lookup_flow(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port,
                                 uint8_t protocol, char *name_out, int name_len) {
    uint32_t pid;

    pid = proc_lookup_flow_cached(pl, src_ip, src_port, protocol, name_out, name_len);
    if (pid != 0) return pid;

    counter_inc(&pl->counters.misses);
    put_unknown(name_out, name_len);
    if (pl->refresh_event && (tick_ms() - pl->last_refresh_ms) >= PROC_MISS_REFRESH_MIN_MS) {
        SetEvent(pl->refresh_event);
    }
    return 0;
}

static uint32_t proc_lookup_flow_retry(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port,
                                       uint8_t protocol, char *name_out, int name_len) {
    uint32_t pid = proc_lookup_flow_cached(pl, src_ip, src_port, protocol, name_out, name_len);
    if (pid != 0) return pid;

    (void)proc_lookup_refresh_if_stale(pl, 0);

    pid = proc_lookup_flow_cached(pl, src_ip, src_port, protocol, name_out, name_len);
    if (pid != 0) return pid;

    if (pl->refresh_event) SetEvent(pl->refresh_event);
    Sleep(1);

    pid = proc_lookup_flow_cached(pl, src_ip, src_port, protocol, name_out, name_len);
    if (pid != 0) return pid;

    counter_inc(&pl->counters.misses);
    put_unknown(name_out, name_len);
    return 0;
}

uint32_t proc_lookup_tcp(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port, char *name_out, int name_len) {
    return proc_lookup_flow(pl, src_ip, src_port, WTP_IPPROTO_TCP, name_out, name_len);
}

uint32_t proc_lookup_udp(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port, char *name_out, int name_len) {
    return proc_lookup_flow(pl, src_ip, src_port, WTP_IPPROTO_UDP, name_out, name_len);
}

uint32_t proc_lookup_tcp_retry(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port, char *name_out, int name_len) {
    return proc_lookup_flow_retry(pl, src_ip, src_port, WTP_IPPROTO_TCP, name_out, name_len);
}

uint32_t proc_lookup_udp_retry(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port, char *name_out, int name_len) {
    return proc_lookup_flow_retry(pl, src_ip, src_port, WTP_IPPROTO_UDP, name_out, name_len);
}

int proc_is_self(proc_lookup_t *pl, uint32_t pid) {
    return pid == pl->self_pid;
}

void proc_lookup_snapshot_counters(proc_lookup_t *pl, proc_lookup_counters_t *out) {
    memset(out, 0, sizeof(*out));
    out->flow_hits = InterlockedExchange64(&pl->counters.flow_hits, 0);
    out->wildcard_hits = InterlockedExchange64(&pl->counters.wildcard_hits, 0);
    out->misses = InterlockedExchange64(&pl->counters.misses, 0);
    out->refreshes = InterlockedExchange64(&pl->counters.refreshes, 0);
    out->flow_events = InterlockedExchange64(&pl->counters.flow_events, 0);
    out->pid_hits = InterlockedExchange64(&pl->counters.pid_hits, 0);
    out->pid_misses = InterlockedExchange64(&pl->counters.pid_misses, 0);
    out->pool_exhausted = InterlockedExchange64(&pl->counters.pool_exhausted, 0);
}
