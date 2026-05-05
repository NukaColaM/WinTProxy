#include "process.h"
#include "log.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>
#include <iphlpapi.h>
#include <psapi.h>

void proc_lookup_init(proc_lookup_t *pl) {
    memset(pl, 0, sizeof(*pl));
    for (int i = 0; i < PROC_CACHE_BUCKETS; i++) {
        InitializeSRWLock(&pl->locks[i]);
    }
    pl->self_pid = GetCurrentProcessId();
}

void proc_lookup_shutdown(proc_lookup_t *pl) {
    for (int i = 0; i < PROC_CACHE_BUCKETS; i++) {
        AcquireSRWLockExclusive(&pl->locks[i]);
        proc_cache_entry_t *e = pl->buckets[i];
        while (e) {
            proc_cache_entry_t *next = e->next;
            free(e);
            e = next;
        }
        pl->buckets[i] = NULL;
        ReleaseSRWLockExclusive(&pl->locks[i]);
    }
}

static uint32_t make_cache_key(uint32_t ip, uint16_t port, int is_udp) {
    return ip ^ ((uint32_t)port << 16) ^ (is_udp ? 0x80000000 : 0);
}

static int cache_get(proc_lookup_t *pl, uint32_t key, uint32_t *pid, char *name, int name_len) {
    unsigned int idx = key % PROC_CACHE_BUCKETS;
    uint64_t now = GetTickCount64();

    AcquireSRWLockShared(&pl->locks[idx]);
    proc_cache_entry_t *e = pl->buckets[idx];
    while (e) {
        uint64_t ttl = (e->pid == 0) ? PROC_CACHE_NEG_TTL_MS : PROC_CACHE_TTL_MS;
        if (e->key == key && (now - e->timestamp) < ttl) {
            *pid = e->pid;
            if (name && name_len > 0) safe_str_copy(name, (size_t)name_len, e->name[0] ? e->name : "unknown");
            ReleaseSRWLockShared(&pl->locks[idx]);
            return 1;
        }
        e = e->next;
    }
    ReleaseSRWLockShared(&pl->locks[idx]);
    return 0;
}

static void cache_put(proc_lookup_t *pl, uint32_t key, uint32_t pid, const char *name) {
    unsigned int idx = key % PROC_CACHE_BUCKETS;

    AcquireSRWLockExclusive(&pl->locks[idx]);

    proc_cache_entry_t *e = pl->buckets[idx];
    while (e) {
        if (e->key == key) {
            e->pid = pid;
            safe_str_copy(e->name, sizeof(e->name), name ? name : "unknown");
            e->timestamp = GetTickCount64();
            ReleaseSRWLockExclusive(&pl->locks[idx]);
            return;
        }
        e = e->next;
    }

    e = (proc_cache_entry_t *)calloc(1, sizeof(proc_cache_entry_t));
    if (e) {
        e->key = key;
        e->pid = pid;
        safe_str_copy(e->name, sizeof(e->name), name ? name : "unknown");
        e->timestamp = GetTickCount64();
        e->next = pl->buckets[idx];
        pl->buckets[idx] = e;
    }

    ReleaseSRWLockExclusive(&pl->locks[idx]);
}

static int get_process_name(uint32_t pid, char *name, int name_len) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return 0;

    WCHAR wpath[MAX_PATH];
    DWORD wpath_len = MAX_PATH;
    if (QueryFullProcessImageNameW(hProc, 0, wpath, &wpath_len)) {
        WCHAR *slash = wcsrchr(wpath, L'\\');
        WCHAR *fname = slash ? slash + 1 : wpath;
        WideCharToMultiByte(CP_UTF8, 0, fname, -1, name, name_len, NULL, NULL);
        CloseHandle(hProc);
        return 1;
    }

    CloseHandle(hProc);
    return 0;
}

uint32_t proc_lookup_tcp(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port, char *name_out, int name_len) {
    uint32_t key = make_cache_key(src_ip, src_port, 0);
    uint32_t pid = 0;

    if (cache_get(pl, key, &pid, name_out, name_len)) {
        return pid;
    }

    PMIB_TCPTABLE_OWNER_PID table = NULL;
    DWORD size = 0;
    DWORD ret = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (ret != ERROR_INSUFFICIENT_BUFFER) {
        cache_put(pl, key, 0, "unknown");
        return 0;
    }

    table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!table) {
        cache_put(pl, key, 0, "unknown");
        return 0;
    }

    ret = GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (ret != NO_ERROR) {
        free(table);
        cache_put(pl, key, 0, "unknown");
        return 0;
    }

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *row = &table->table[i];
        if (row->dwLocalAddr == src_ip && (uint16_t)ntohs((u_short)row->dwLocalPort) == src_port) {
            pid = row->dwOwningPid;
            break;
        }
    }
    free(table);

    if (pid > 0) {
        char proc_name[256] = {0};
        if (get_process_name(pid, proc_name, sizeof(proc_name))) {
            if (name_out && name_len > 0) safe_str_copy(name_out, (size_t)name_len, proc_name);
            cache_put(pl, key, pid, proc_name);
        } else {
            cache_put(pl, key, pid, "unknown");
            if (name_out && name_len > 0) safe_str_copy(name_out, (size_t)name_len, "unknown");
        }
    } else {
        cache_put(pl, key, 0, "unknown");
        if (name_out && name_len > 0) safe_str_copy(name_out, (size_t)name_len, "unknown");
    }

    return pid;
}

uint32_t proc_lookup_udp(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port, char *name_out, int name_len) {
    uint32_t key = make_cache_key(src_ip, src_port, 1);
    uint32_t pid = 0;

    if (cache_get(pl, key, &pid, name_out, name_len)) {
        return pid;
    }

    PMIB_UDPTABLE_OWNER_PID table = NULL;
    DWORD size = 0;
    DWORD ret = GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (ret != ERROR_INSUFFICIENT_BUFFER) {
        cache_put(pl, key, 0, "unknown");
        return 0;
    }

    table = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
    if (!table) {
        cache_put(pl, key, 0, "unknown");
        return 0;
    }

    ret = GetExtendedUdpTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (ret != NO_ERROR) {
        free(table);
        cache_put(pl, key, 0, "unknown");
        return 0;
    }

    uint32_t fallback_pid = 0;

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_UDPROW_OWNER_PID *row = &table->table[i];
        uint16_t local_port = (uint16_t)ntohs((u_short)row->dwLocalPort);
        if (local_port == src_port) {
            if (row->dwLocalAddr == src_ip) {
                pid = row->dwOwningPid;
                break;
            }
            if (row->dwLocalAddr == 0) {
                fallback_pid = row->dwOwningPid;
            }
        }
    }
    free(table);

    if (pid == 0) pid = fallback_pid;

    if (pid > 0) {
        char proc_name[256] = {0};
        if (get_process_name(pid, proc_name, sizeof(proc_name))) {
            if (name_out && name_len > 0) safe_str_copy(name_out, (size_t)name_len, proc_name);
            cache_put(pl, key, pid, proc_name);
        } else {
            cache_put(pl, key, pid, "unknown");
            if (name_out && name_len > 0) safe_str_copy(name_out, (size_t)name_len, "unknown");
        }
    } else {
        cache_put(pl, key, 0, "unknown");
        if (name_out && name_len > 0) safe_str_copy(name_out, (size_t)name_len, "unknown");
    }

    return pid;
}

int proc_is_self(proc_lookup_t *pl, uint32_t pid) {
    return pid == pl->self_pid;
}
