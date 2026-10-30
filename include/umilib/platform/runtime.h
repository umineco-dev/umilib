/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PLATFORM_RUNTIME_H
#define UMILIB_PLATFORM_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"
#include "umilib/runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A pool of threads that run callback tasks.
 */
typedef struct umilib_platform_runtime_ThreadPool umilib_platform_runtime_ThreadPool;

/**
 * A handle that spawns tasks on a thread pool while it exists.
 */
typedef struct umilib_platform_runtime_PoolSpawner umilib_platform_runtime_PoolSpawner;

/**
 * A thread that waits on the system's I/O and wakes timers.
 */
typedef struct umilib_platform_runtime_Reactor umilib_platform_runtime_Reactor;

/**
 * Writes a new pool of `threads` threads (0 for as many as the system's parallelism) into `out`.
 */
const umilib_ffi_Status* umilib_platform_runtime_thread_pool_new(size_t threads, umilib_platform_runtime_ThreadPool** out);

/**
 * Releases a pool: stops its threads (after the polls they are making) and drops the tasks
 * left, calling their drop callbacks. Does nothing if `pool` is null.
 */
void umilib_platform_runtime_thread_pool_free(umilib_platform_runtime_ThreadPool* pool);

/**
 * Writes the threads of the pool into `out`.
 */
const umilib_ffi_Status* umilib_platform_runtime_thread_pool_threads(const umilib_platform_runtime_ThreadPool* pool, size_t* out);

/**
 * Writes a spawner of the pool into `out`: tasks keep one to spawn more (spawning through
 * the pool itself from a task would wait for the pool's users in some bindings). Once the
 * pool is released or stopped, the tasks it spawns are dropped at once.
 */
const umilib_ffi_Status* umilib_platform_runtime_thread_pool_spawner(const umilib_platform_runtime_ThreadPool* pool, umilib_platform_runtime_PoolSpawner** out);

/**
 * Releases a spawner. Does nothing if `spawner` is null.
 */
void umilib_platform_runtime_pool_spawner_free(umilib_platform_runtime_PoolSpawner* spawner);

/**
 * Spawns the task of `poll`, `drop` (may be null) and `context` on the pool of the spawner,
 * and writes its handle into `out`. The context must be usable from any thread of the pool.
 */
const umilib_ffi_Status* umilib_platform_runtime_pool_spawner_spawn(const umilib_platform_runtime_PoolSpawner* spawner, umilib_runtime_TaskPoll poll, umilib_runtime_TaskDrop drop, void* context, umilib_runtime_JoinHandle** out);

/**
 * Blocks the calling thread until the task of `handle` is done; fails with `Cancelled` if it
 * was aborted or dropped (its pool stopped). It needs no pool: any thread may wait.
 */
const umilib_ffi_Status* umilib_platform_runtime_thread_pool_block_on_thread(umilib_runtime_JoinHandle* handle);

/**
 * Stops the threads of the pool (after the polls they are making) and drops the tasks left,
 * calling their drop callbacks; tasks spawned afterwards are dropped at once.
 */
const umilib_ffi_Status* umilib_platform_runtime_thread_pool_shutdown(const umilib_platform_runtime_ThreadPool* pool);

/**
 * Writes the nanoseconds of the system's monotonic clock since the process first read it into `out`.
 */
const umilib_ffi_Status* umilib_platform_runtime_monotonic_clock_now(uint64_t* out);

/**
 * Writes a new reactor (its thread started) into `out`.
 */
const umilib_ffi_Status* umilib_platform_runtime_reactor_new(umilib_platform_runtime_Reactor** out);

/**
 * Releases a reactor (its thread stops once nothing uses it). Does nothing if `reactor` is null.
 */
void umilib_platform_runtime_reactor_free(umilib_platform_runtime_Reactor* reactor);

/**
 * Writes the nanoseconds of the reactor's clock (the monotonic clock) into `out`.
 */
const umilib_ffi_Status* umilib_platform_runtime_reactor_now(const umilib_platform_runtime_Reactor* reactor, uint64_t* out);

/**
 * Wakes `waker` once the reactor's clock reaches `deadline` (nanoseconds; at once if it has)
 * and writes the key of the timer into `key`: a task that stops waiting removes it.
 */
const umilib_ffi_Status* umilib_platform_runtime_reactor_wake_at(const umilib_platform_runtime_Reactor* reactor, uint64_t deadline, const umilib_runtime_Waker* waker, uint64_t* key);

/**
 * Removes the timer `key` of `_wake_at` and writes whether it was waiting into `removed`.
 */
const umilib_ffi_Status* umilib_platform_runtime_reactor_remove(const umilib_platform_runtime_Reactor* reactor, uint64_t key, bool* removed);

#ifdef __cplusplus
}
#endif

#endif
