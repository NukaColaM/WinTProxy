#ifndef WINTPROXY_TEST_WINDOWS_H
#define WINTPROXY_TEST_WINDOWS_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>

#define __stdcall
#define WINAPI
#define WSAAPI
#define CALLBACK
#define VOID void

typedef void *HANDLE;
typedef HANDLE HWND;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef char *LPSTR;
typedef const char *LPCSTR;
typedef const wchar_t *LPCWSTR;
typedef wchar_t WCHAR;
typedef WCHAR *LPWSTR;
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef int64_t LONG64;
typedef uint64_t ULONGLONG;
typedef uintptr_t ULONG_PTR;
typedef uintptr_t DWORD_PTR;
typedef intptr_t INT_PTR;
typedef uintptr_t UINT_PTR;
typedef unsigned int UINT;
typedef unsigned long ULONG;
typedef uint16_t USHORT;
typedef uint8_t UCHAR;
typedef int BOOL;
typedef long HRESULT;
typedef void *PVOID;
typedef DWORD *PDWORD;
typedef ULONG *PULONG;
typedef UCHAR *PUCHAR;
typedef char *PCHAR;
typedef wchar_t *PWCHAR;
typedef void *LPSECURITY_ATTRIBUTES;
typedef uint32_t COLORREF;
typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME;
typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME;
typedef struct _SYSTEM_INFO {
    union {
        DWORD dwOemId;
        struct {
            WORD wProcessorArchitecture;
            WORD wReserved;
        };
    };
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
} SYSTEM_INFO;
typedef struct _TIME_ZONE_INFORMATION {
    LONG Bias;
    wchar_t StandardName[32];
    FILETIME StandardDate;
    LONG StandardBias;
    wchar_t DaylightName[32];
    FILETIME DaylightDate;
    LONG DaylightBias;
} TIME_ZONE_INFORMATION;
typedef struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY;

typedef struct _ULARGE_INTEGER {
    uint64_t QuadPart;
} ULARGE_INTEGER;

typedef struct _SRWLOCK {
    void *opaque;
} SRWLOCK;

typedef struct _GUID {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} GUID;

typedef struct _CRITICAL_SECTION {
    void *opaque;
} CRITICAL_SECTION;

typedef struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    DWORD Offset;
    DWORD OffsetHigh;
    HANDLE hEvent;
} OVERLAPPED;

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)(-1))
#define WAIT_OBJECT_0 0
#define INFINITE 0xFFFFFFFFU
#define STD_ERROR_HANDLE ((DWORD)-12)
#define CP_UTF8 65001
#define TEXT(x) x

static inline DWORD GetLastError(void) {
    return 0;
}

static inline void SetLastError(DWORD err) {
    (void)err;
}

static inline DWORD GetCurrentThreadId(void) {
    return 1;
}

static inline DWORD GetTickCount(void) {
    return 0;
}

static inline uint64_t GetTickCount64(void) {
    return 0;
}

static inline void GetLocalTime(SYSTEMTIME *st) {
    if (st) memset(st, 0, sizeof(*st));
}

static inline void GetSystemInfo(SYSTEM_INFO *info) {
    if (info) {
        memset(info, 0, sizeof(*info));
        info->dwNumberOfProcessors = 4;
    }
}

static inline HANDLE GetStdHandle(DWORD nStdHandle) {
    (void)nStdHandle;
    return INVALID_HANDLE_VALUE;
}

static inline BOOL GetConsoleMode(HANDLE hConsoleHandle, DWORD *lpMode) {
    (void)hConsoleHandle;
    if (lpMode) *lpMode = 0;
    return FALSE;
}

static inline BOOL SetConsoleMode(HANDLE hConsoleHandle, DWORD dwMode) {
    (void)hConsoleHandle;
    (void)dwMode;
    return FALSE;
}

static inline int WideCharToMultiByte(unsigned int CodePage, DWORD dwFlags,
                                      const wchar_t *lpWideCharStr, int cchWideChar,
                                      char *lpMultiByteStr, int cbMultiByte,
                                      const char *lpDefaultChar, BOOL *lpUsedDefaultChar) {
    (void)CodePage; (void)dwFlags; (void)lpDefaultChar; (void)lpUsedDefaultChar;
    if (!lpWideCharStr || !lpMultiByteStr || cbMultiByte <= 0) return 0;
    if (cchWideChar < 0) cchWideChar = 0;
    if (cchWideChar > 0) {
        size_t i;
        for (i = 0; i < (size_t)cchWideChar && i + 1 < (size_t)cbMultiByte; i++) {
            lpMultiByteStr[i] = (char)(lpWideCharStr[i] & 0x7F);
            if (lpWideCharStr[i] == L'\0') return (int)i;
        }
        if (i < (size_t)cbMultiByte) lpMultiByteStr[i] = '\0';
    }
    return 0;
}

static inline int GetConsoleOutputCP(void) {
    return 65001;
}

typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

#ifdef WINTPROXY_TEST_HOOKS
extern int g_test_windows_create_thread_count;
extern LPTHREAD_START_ROUTINE g_test_windows_thread_procs[64];
extern LPVOID g_test_windows_thread_params[64];
extern int g_test_windows_set_event_count;
extern HANDLE g_test_windows_set_event_handles[128];
#endif

static inline BOOL CloseHandle(HANDLE hObject) {
    (void)hObject;
    return TRUE;
}

static inline DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    (void)hHandle;
    (void)dwMilliseconds;
    return 0;
}

static inline BOOL SetEvent(HANDLE hEvent) {
#ifdef WINTPROXY_TEST_HOOKS
    if (g_test_windows_set_event_count < 128) {
        g_test_windows_set_event_handles[g_test_windows_set_event_count] = hEvent;
    }
    g_test_windows_set_event_count++;
#else
    (void)hEvent;
#endif
    return TRUE;
}

static inline BOOL ResetEvent(HANDLE hEvent) {
    (void)hEvent;
    return TRUE;
}

static inline HANDLE CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset,
                                  BOOL bInitialState, LPCSTR lpName) {
    static uintptr_t next_event = 0x1000;

    (void)lpEventAttributes; (void)bManualReset; (void)bInitialState; (void)lpName;
    next_event += 0x10;
    return (HANDLE)next_event;
}

#ifndef CreateEvent
#define CreateEvent CreateEventA
#endif

static inline HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, size_t dwStackSize,
                                  LPVOID lpStartAddress, LPVOID lpParameter,
                                  DWORD dwCreationFlags, DWORD *lpThreadId) {
    (void)lpThreadAttributes; (void)dwStackSize; (void)lpStartAddress;
    (void)lpParameter; (void)dwCreationFlags;
#ifdef WINTPROXY_TEST_HOOKS
    if (g_test_windows_create_thread_count < 64) {
        g_test_windows_thread_procs[g_test_windows_create_thread_count] =
            (LPTHREAD_START_ROUTINE)lpStartAddress;
        g_test_windows_thread_params[g_test_windows_create_thread_count] =
            lpParameter;
    }
    g_test_windows_create_thread_count++;
#endif
    if (lpThreadId) *lpThreadId = 1;
    return (HANDLE)1;
}

static inline void Sleep(DWORD dwMilliseconds) {
    (void)dwMilliseconds;
}

static inline LONG InterlockedIncrement(LONG volatile *Addend) {
    return ++(*Addend);
}

static inline LONG InterlockedDecrement(LONG volatile *Addend) {
    return --(*Addend);
}

static inline LONG64 InterlockedIncrement64(LONG64 volatile *Addend) {
    return ++(*Addend);
}

static inline LONG64 InterlockedDecrement64(LONG64 volatile *Addend) {
    return --(*Addend);
}

static inline LONG64 InterlockedAdd64(LONG64 volatile *Addend, LONG64 Value) {
    return (*Addend += Value);
}

static inline LONG64 InterlockedExchange64(LONG64 volatile *Target, LONG64 Value) {
    LONG64 old = *Target;
    *Target = Value;
    return old;
}

static inline LONG64 InterlockedCompareExchange64(LONG64 volatile *Destination,
                                                  LONG64 Exchange, LONG64 Comperand) {
    LONG64 old = *Destination;
    if (old == Comperand) *Destination = Exchange;
    return old;
}

static inline void InitializeSRWLock(SRWLOCK *lock) {
    if (lock) lock->opaque = NULL;
}

static inline void AcquireSRWLockShared(SRWLOCK *lock) {
    (void)lock;
}

static inline void ReleaseSRWLockShared(SRWLOCK *lock) {
    (void)lock;
}

static inline void AcquireSRWLockExclusive(SRWLOCK *lock) {
    (void)lock;
}

static inline void ReleaseSRWLockExclusive(SRWLOCK *lock) {
    (void)lock;
}

typedef struct _WSADATA {
    WORD wVersion;
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char *lpVendorInfo;
} WSADATA;

static inline int WSAStartup(WORD wVersionRequested, WSADATA *lpWSAData) {
    (void)wVersionRequested;
    if (lpWSAData) memset(lpWSAData, 0, sizeof(*lpWSAData));
    return 0;
}

static inline int WSACleanup(void) {
    return 0;
}

#endif
