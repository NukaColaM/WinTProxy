#ifndef WINTPROXY_PROCESS_H
#define WINTPROXY_PROCESS_H

#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#endif

#define PROC_CACHE_BUCKETS 1024
#define PROC_CACHE_TTL_MS  1000

typedef struct proc_cache_entry_s {
    uint32_t key;
    uint32_t pid;
    char     name[256];
    uint64_t timestamp;
    struct proc_cache_entry_s *next;
} proc_cache_entry_t;

typedef struct {
    proc_cache_entry_t *buckets[PROC_CACHE_BUCKETS];
    SRWLOCK             lock;
    uint32_t            self_pid;
} proc_lookup_t;

void proc_lookup_init(proc_lookup_t *pl);
void proc_lookup_shutdown(proc_lookup_t *pl);

uint32_t proc_lookup_tcp(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port, char *name_out, int name_len);
uint32_t proc_lookup_udp(proc_lookup_t *pl, uint32_t src_ip, uint16_t src_port, char *name_out, int name_len);

int proc_is_self(proc_lookup_t *pl, uint32_t pid);

#endif
