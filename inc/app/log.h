#ifndef WINTPROXY_APP_LOG_H
#define WINTPROXY_APP_LOG_H

typedef enum {
    LOG_ERROR = 0,
    LOG_WARN  = 1,
    LOG_INFO  = 2,
    LOG_DEBUG = 3,
    LOG_TRACE = 4,
    LOG_PACKET = 5
} log_level_t;

void log_init(log_level_t level, const char *log_file_path);
void log_shutdown(void);

int  log_is_enabled(log_level_t level);
void log_write(log_level_t level, const char *fmt, ...);

#define LOG_ERROR(fmt, ...)  do { if (log_is_enabled(LOG_ERROR))  log_write(LOG_ERROR,  fmt, ##__VA_ARGS__); } while (0)
#define LOG_WARN(fmt, ...)   do { if (log_is_enabled(LOG_WARN))   log_write(LOG_WARN,   fmt, ##__VA_ARGS__); } while (0)
#define LOG_INFO(fmt, ...)   do { if (log_is_enabled(LOG_INFO))   log_write(LOG_INFO,   fmt, ##__VA_ARGS__); } while (0)
#define LOG_DEBUG(fmt, ...)  do { if (log_is_enabled(LOG_DEBUG))  log_write(LOG_DEBUG,  fmt, ##__VA_ARGS__); } while (0)
#define LOG_TRACE(fmt, ...)  do { if (log_is_enabled(LOG_TRACE))  log_write(LOG_TRACE,  fmt, ##__VA_ARGS__); } while (0)
#define LOG_PACKET(fmt, ...) do { if (log_is_enabled(LOG_PACKET)) log_write(LOG_PACKET, fmt, ##__VA_ARGS__); } while (0)

#endif
