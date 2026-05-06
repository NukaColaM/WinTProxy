#include "log.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#define LOG_SHARD_COUNT        16
#define LOG_SHARD_CAPACITY     4096
#define LOG_MESSAGE_MAX        1024
#define LOG_FLUSH_INTERVAL_MS  250

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

typedef struct {
    log_level_t level;
    char        time_str[32];
    DWORD       tid;
    char        message[LOG_MESSAGE_MAX];
} log_entry_t;

typedef struct {
    log_entry_t *entries;
    unsigned int head;
    unsigned int tail;
    unsigned int count;
    unsigned long dropped;
    CRITICAL_SECTION lock;
} log_shard_t;

typedef struct {
    log_shard_t shards[LOG_SHARD_COUNT];
    volatile int running;
    int initialized;
    int use_color;
    HANDLE thread;
} log_queue_t;

static log_level_t  g_log_level = LOG_INFO;
static FILE        *g_log_file = NULL;
static log_queue_t  g_log_queue;
static CRITICAL_SECTION g_output_lock;
static int g_output_lock_init = 0;

static const char *level_names[] = { "ERROR", "WARN", "INFO", "DEBUG", "TRACE", "PKT" };
static const char *level_colors[] = { "\033[31m", "\033[33m", "\033[32m", "\033[36m", "\033[90m", "\033[35m" };

static void log_output_entry(const log_entry_t *entry);
static void log_output_dropped(unsigned long dropped);
static DWORD WINAPI log_worker_proc(LPVOID param);

int log_is_enabled(log_level_t level) {
    return level <= g_log_level;
}

void log_init(log_level_t level, const char *log_file_path) {
    int async_ready = 1;
    g_log_level = level;

    if (log_file_path && log_file_path[0]) {
        g_log_file = fopen(log_file_path, "a");
        if (!g_log_file) fprintf(stderr, "WARNING: Cannot open log file: %s\n", log_file_path);
    }

    memset(&g_log_queue, 0, sizeof(g_log_queue));
    g_log_queue.running = 1;

    InitializeCriticalSection(&g_output_lock);
    g_output_lock_init = 1;

    for (int i = 0; i < LOG_SHARD_COUNT; i++) {
        InitializeCriticalSection(&g_log_queue.shards[i].lock);
        g_log_queue.shards[i].entries = (log_entry_t *)calloc(LOG_SHARD_CAPACITY, sizeof(log_entry_t));
        if (!g_log_queue.shards[i].entries) {
            async_ready = 0;
        }
    }
    g_log_queue.initialized = 1;

    {
        HANDLE hConsole = GetStdHandle(STD_ERROR_HANDLE);
        DWORD mode;
        if (GetConsoleMode(hConsole, &mode) != 0 &&
            SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0) {
            g_log_queue.use_color = 1;
        } else {
            g_log_queue.use_color = 0;
        }
    }

    if (async_ready) {
        g_log_queue.thread = CreateThread(NULL, 0, log_worker_proc, &g_log_queue, 0, NULL);
    }
    if (!async_ready || !g_log_queue.thread) {
        g_log_queue.running = 0;
        fprintf(stderr, "WARNING: Cannot start logger thread; falling back to synchronous logging\n");
    }
}

void log_shutdown(void) {
    if (g_log_queue.thread) {
        g_log_queue.running = 0;
        WaitForSingleObject(g_log_queue.thread, INFINITE);
        CloseHandle(g_log_queue.thread);
        g_log_queue.thread = NULL;
    }
    if (g_log_queue.initialized) {
        for (int i = 0; i < LOG_SHARD_COUNT; i++) {
            free(g_log_queue.shards[i].entries);
            g_log_queue.shards[i].entries = NULL;
            DeleteCriticalSection(&g_log_queue.shards[i].lock);
        }
        g_log_queue.initialized = 0;
    }
    if (g_output_lock_init) {
        DeleteCriticalSection(&g_output_lock);
        g_output_lock_init = 0;
    }

    fflush(stderr);
    if (g_log_file) { fflush(g_log_file); fclose(g_log_file); g_log_file = NULL; }
}

static void log_output_entry_unlocked(const log_entry_t *entry) {
    if (g_log_queue.use_color) fprintf(stderr, "%s", level_colors[entry->level]);
    fprintf(stderr, "[%s][TID:%lu][%-5s] ", entry->time_str, entry->tid, level_names[entry->level]);
    if (g_log_queue.use_color) fprintf(stderr, "\033[0m");
    fprintf(stderr, "%s\n", entry->message);

    if (g_log_file) {
        fprintf(g_log_file, "[%s][TID:%lu][%-5s] %s\n",
                entry->time_str, entry->tid, level_names[entry->level], entry->message);
    }
}

static void log_output_entry(const log_entry_t *entry) {
    if (g_output_lock_init) EnterCriticalSection(&g_output_lock);
    log_output_entry_unlocked(entry);
    if (g_output_lock_init) LeaveCriticalSection(&g_output_lock);
}

static void log_output_dropped(unsigned long dropped) {
    if (dropped == 0) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    DWORD tid = GetCurrentThreadId();
    char time_str[32];
    snprintf(time_str, sizeof(time_str), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    if (g_output_lock_init) EnterCriticalSection(&g_output_lock);
    fprintf(stderr, "[%s][TID:%lu][WARN ] dropped %lu log entries\n", time_str, tid, dropped);
    if (g_log_file) {
        fprintf(g_log_file, "[%s][TID:%lu][WARN ] dropped %lu log entries\n", time_str, tid, dropped);
    }
    if (g_output_lock_init) LeaveCriticalSection(&g_output_lock);
}

static DWORD WINAPI log_worker_proc(LPVOID param) {
    log_queue_t *q = (log_queue_t *)param;
    DWORD last_flush = GetTickCount();

    for (;;) {
        int drained = 0;

        for (int s = 0; s < LOG_SHARD_COUNT; s++) {
            log_shard_t *shard = &q->shards[s];
            if (shard->count == 0 && shard->dropped == 0) continue;

            if (TryEnterCriticalSection(&shard->lock)) {
                while (shard->count > 0) {
                    log_entry_t entry = shard->entries[shard->tail];
                    shard->tail = (shard->tail + 1) % LOG_SHARD_CAPACITY;
                    shard->count--;
                    LeaveCriticalSection(&shard->lock);
                    log_output_entry(&entry);
                    drained++;
                    EnterCriticalSection(&shard->lock);
                }
                if (shard->dropped > 0) {
                    unsigned long d = shard->dropped;
                    shard->dropped = 0;
                    LeaveCriticalSection(&shard->lock);
                    log_output_dropped(d);
                    EnterCriticalSection(&shard->lock);
                }
                LeaveCriticalSection(&shard->lock);
            }
        }

        if (drained == 0 && q->running) {
            Sleep(1);
        }

        DWORD now = GetTickCount();
        if ((now - last_flush) >= LOG_FLUSH_INTERVAL_MS) {
            fflush(stderr);
            if (g_log_file) fflush(g_log_file);
            last_flush = now;
        }

        if (!q->running) {
            /* Final drain: force-drain all shards */
            for (int s = 0; s < LOG_SHARD_COUNT; s++) {
                log_shard_t *shard = &q->shards[s];
                EnterCriticalSection(&shard->lock);
                while (shard->count > 0) {
                    log_entry_t entry = shard->entries[shard->tail];
                    shard->tail = (shard->tail + 1) % LOG_SHARD_CAPACITY;
                    shard->count--;
                    LeaveCriticalSection(&shard->lock);
                    log_output_entry(&entry);
                    EnterCriticalSection(&shard->lock);
                }
                if (shard->dropped > 0) {
                    unsigned long d = shard->dropped;
                    shard->dropped = 0;
                    LeaveCriticalSection(&shard->lock);
                    log_output_dropped(d);
                } else {
                    LeaveCriticalSection(&shard->lock);
                }
            }
            break;
        }
    }

    fflush(stderr);
    if (g_log_file) fflush(g_log_file);
    return 0;
}

void log_write(log_level_t level, const char *fmt, ...) {
    if (level > g_log_level) return;

    log_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.level = level;

    SYSTEMTIME st;
    GetLocalTime(&st);
    entry.tid = GetCurrentThreadId();
    snprintf(entry.time_str, sizeof(entry.time_str), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, fmt);
    vsnprintf(entry.message, sizeof(entry.message), fmt, args);
    va_end(args);

    /* Synchronous fallback: worker thread not available */
    if (!g_log_queue.thread) {
        log_output_entry(&entry);
        fflush(stderr);
        if (g_log_file) fflush(g_log_file);
        return;
    }

    /* Sharded async path: pick shard by thread ID, O(1) insert, O(1) on full */
    unsigned int s = entry.tid % LOG_SHARD_COUNT;
    log_shard_t *shard = &g_log_queue.shards[s];
    if (!shard->entries) {
        log_output_entry(&entry);
        return;
    }

    EnterCriticalSection(&shard->lock);
    if (shard->count < LOG_SHARD_CAPACITY) {
        shard->entries[shard->head] = entry;
        shard->head = (shard->head + 1) % LOG_SHARD_CAPACITY;
        shard->count++;
    } else {
        shard->dropped++;
    }
    LeaveCriticalSection(&shard->lock);
}
