/*
 * platform.h - OS abstraction: threads, mutexes, atomics, monotonic clock.
 *
 * POSIX (macOS/Linux): pthreads + GCC/Clang __atomic builtins.
 * Windows: Win32 threads + Interlocked* (works with MSVC and clang-cl).
 */
#ifndef ZR_PLATFORM_H
#define ZR_PLATFORM_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#if defined(_WIN32)
#define ZR_WINDOWS 1
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

typedef HANDLE            zr_thread_t;
typedef CRITICAL_SECTION  zr_mutex_t;
typedef volatile LONG64   zr_atomic_u64;

static inline int zr_thread_create(zr_thread_t *t, unsigned (__stdcall *fn)(void *), void *arg) {
    *t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fn, arg, 0, NULL);
    return *t ? 0 : -1;
}
static inline void zr_thread_join(zr_thread_t t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
static inline void zr_mutex_init(zr_mutex_t *m) { InitializeCriticalSection(m); }
static inline void zr_mutex_lock(zr_mutex_t *m) { EnterCriticalSection(m); }
static inline void zr_mutex_unlock(zr_mutex_t *m) { LeaveCriticalSection(m); }
static inline void zr_mutex_destroy(zr_mutex_t *m) { DeleteCriticalSection(m); }

static inline uint64_t zr_atomic_load(const zr_atomic_u64 *p) { return (uint64_t)InterlockedCompareExchange64((LONG64 *)p, 0, 0); }
static inline void     zr_atomic_store(zr_atomic_u64 *p, uint64_t v) { InterlockedExchange64((LONG64 *)p, (LONG64)v); }
static inline uint64_t zr_atomic_add(zr_atomic_u64 *p, uint64_t v) { return (uint64_t)InterlockedExchangeAdd64((LONG64 *)p, (LONG64)v); }
static inline uint64_t zr_atomic_fetch_add(zr_atomic_u64 *p, uint64_t v) { return (uint64_t)InterlockedExchangeAdd64((LONG64 *)p, (LONG64)v); }
static inline int      zr_atomic_flag_set(zr_atomic_u64 *p) { return (int)InterlockedExchange64((LONG64 *)p, 1); }

static inline double zr_now(void) {
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER c;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)freq.QuadPart;
}
static inline void zr_sleep_ms(unsigned ms) { Sleep(ms); }

static inline unsigned zr_num_cpus(void) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    return si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1;
}
static inline int zr_rename(const char *a, const char *b) {
    return MoveFileExA(a, b, MOVEFILE_REPLACE_EXISTING) ? 0 : -1;
}
static inline void zr_enable_ansi(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) SetConsoleMode(h, mode | 0x0004 /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */);
}

#else /* POSIX */

#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <time.h>
#include <unistd.h>

typedef pthread_t       zr_thread_t;
typedef pthread_mutex_t zr_mutex_t;
typedef uint64_t        zr_atomic_u64;

static inline int zr_thread_create(zr_thread_t *t, void *(*fn)(void *), void *arg) {
    return pthread_create(t, NULL, fn, arg);
}
static inline void zr_thread_join(zr_thread_t t) { pthread_join(t, NULL); }
static inline void zr_mutex_init(zr_mutex_t *m) { pthread_mutex_init(m, NULL); }
static inline void zr_mutex_lock(zr_mutex_t *m) { pthread_mutex_lock(m); }
static inline void zr_mutex_unlock(zr_mutex_t *m) { pthread_mutex_unlock(m); }
static inline void zr_mutex_destroy(zr_mutex_t *m) { pthread_mutex_destroy(m); }

static inline uint64_t zr_atomic_load(const zr_atomic_u64 *p) { return __atomic_load_n(p, __ATOMIC_RELAXED); }
static inline void     zr_atomic_store(zr_atomic_u64 *p, uint64_t v) { __atomic_store_n(p, v, __ATOMIC_RELAXED); }
static inline uint64_t zr_atomic_add(zr_atomic_u64 *p, uint64_t v) { return __atomic_add_fetch(p, v, __ATOMIC_RELAXED); }
static inline uint64_t zr_atomic_fetch_add(zr_atomic_u64 *p, uint64_t v) { return __atomic_fetch_add(p, v, __ATOMIC_RELAXED); }
static inline int      zr_atomic_flag_set(zr_atomic_u64 *p) { return __atomic_exchange_n(p, 1, __ATOMIC_ACQ_REL); }

static inline double zr_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}
static inline void zr_sleep_ms(unsigned ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}
static inline unsigned zr_num_cpus(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (unsigned)n : 1;
}
static inline int zr_rename(const char *a, const char *b) { return rename(a, b); }
static inline void zr_enable_ansi(void) { (void)0; }

#endif

/* ---------- shared endianness / rotate helpers ---------- */
static inline uint16_t zr_rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t zr_rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline uint64_t zr_rd64(const uint8_t *p) { return (uint64_t)zr_rd32(p) | ((uint64_t)zr_rd32(p + 4) << 32); }
static inline uint32_t zr_be32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3]; }
static inline void     zr_wr32be(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static inline uint32_t zr_rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t zr_rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

#endif /* ZR_PLATFORM_H */
