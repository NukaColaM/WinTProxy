#ifndef WINTPROXY_LOG_H
#define WINTPROXY_LOG_H

typedef enum {
    LOG_ERROR = 0,
    LOG_WARN  = 1,
    LOG_INFO  = 2,
    LOG_DEBUG = 3,
    LOG_TRACE = 4
} log_level_t;

void log_init(log_level_t level, const char *log_file_path);
void log_shutdown(void);

void log_write(log_level_t level, const char *fmt, ...);

#define LOG_ERROR(fmt, ...) log_write(LOG_ERROR, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_write(LOG_WARN,  fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_write(LOG_INFO,  fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) log_write(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...) log_write(LOG_TRACE, fmt, ##__VA_ARGS__)

#endif
