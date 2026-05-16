#ifndef WINTPROXY_CORE_COMMON_H
#define WINTPROXY_CORE_COMMON_H

#define WINTPROXY_VERSION  "v0.6.0"

#include <stdint.h>

/* === Error codes ===
 * All functions that can fail return error_t.
 * ERR_OK = 0 so `if (func() != ERR_OK)` works naturally.
 * Pure lookup/query functions keep domain-specific return types.
 */
typedef enum {
    ERR_OK         =  0,
    ERR_GENERIC    = -1,
    ERR_NOT_FOUND  = -2,
    ERR_MEMORY     = -3,
    ERR_NETWORK    = -4,
    ERR_PARAM      = -5,
    ERR_PROTO      = -6,
    ERR_BUSY       = -7,
    ERR_PERMISSION = -8
} error_t;

#endif
