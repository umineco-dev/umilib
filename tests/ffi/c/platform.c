/* Runs tasks of C callbacks on a thread pool of the generated headers, sleeping on a reactor's timer. */
#include <stdio.h>
#include <string.h>

#include "umilib.h"

#define CHECK(condition)                                                                       \
    do {                                                                                       \
        if (!(condition)) {                                                                    \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #condition);      \
            return 1;                                                                          \
        }                                                                                      \
    } while (0)

/* A task that is done once the reactor's clock reaches its deadline. A pool polls it from
   any of its threads, one at a time, so its fields need no lock. */
typedef struct {
    umilib_platform_runtime_Reactor* reactor;
    uint64_t deadline;
    int polls;
    int dropped;
    int removals; /* 2 once a timer was removed, and a second removal found nothing */
} Sleeper;

static bool poll_sleeper(void* context, const umilib_runtime_Waker* waker) {
    Sleeper* sleeper = context;
    uint64_t now = 0;
    sleeper->polls++;
    if (umilib_platform_runtime_reactor_now(sleeper->reactor, &now) != NULL || now >= sleeper->deadline) {
        return true;
    }
    uint64_t key = 0;
    if (sleeper->polls == 1) {
        /* A timer the task no longer waits for is removed by its key, once. */
        bool removed = false;
        if (umilib_platform_runtime_reactor_wake_at(sleeper->reactor, UINT64_MAX, waker, &key) != NULL ||
            umilib_platform_runtime_reactor_remove(sleeper->reactor, key, &removed) != NULL || !removed) {
            return true;
        }
        sleeper->removals++;
        if (umilib_platform_runtime_reactor_remove(sleeper->reactor, key, &removed) != NULL || removed) {
            return true;
        }
        sleeper->removals++;
    }
    return umilib_platform_runtime_reactor_wake_at(sleeper->reactor, sleeper->deadline, waker, &key) != NULL;
}

static void drop_sleeper(void* context) {
    ((Sleeper*)context)->dropped = 1;
}

int main(void) {
    uint64_t first = 0, second = 0;
    CHECK(umilib_platform_runtime_monotonic_clock_now(&first) == NULL);
    CHECK(umilib_platform_runtime_monotonic_clock_now(&second) == NULL);
    CHECK(second >= first);

    umilib_platform_runtime_Reactor* reactor = NULL;
    CHECK(umilib_platform_runtime_reactor_new(&reactor) == NULL);
    umilib_platform_runtime_ThreadPool* pool = NULL;
    CHECK(umilib_platform_runtime_thread_pool_new(2, &pool) == NULL);
    size_t threads = 0;
    CHECK(umilib_platform_runtime_thread_pool_threads(pool, &threads) == NULL);
    CHECK(threads == 2);

    uint64_t start = 0;
    CHECK(umilib_platform_runtime_reactor_now(reactor, &start) == NULL);
    Sleeper sleeper = {reactor, start + 20000000u, 0, 0, 0};
    umilib_platform_runtime_PoolSpawner* spawner = NULL;
    CHECK(umilib_platform_runtime_thread_pool_spawner(pool, &spawner) == NULL);
    umilib_runtime_JoinHandle* handle = NULL;
    CHECK(umilib_platform_runtime_pool_spawner_spawn(spawner, poll_sleeper, drop_sleeper, &sleeper, &handle) == NULL);
    CHECK(umilib_platform_runtime_thread_pool_block_on_thread(handle) == NULL);
    umilib_runtime_join_handle_free(handle);
    uint64_t end = 0;
    CHECK(umilib_platform_runtime_reactor_now(reactor, &end) == NULL);
    CHECK(end >= sleeper.deadline);
    CHECK(sleeper.polls >= 2);
    CHECK(sleeper.removals == 2);

    /* A task spawned on a stopped pool is dropped at once and reported cancelled. */
    CHECK(umilib_platform_runtime_thread_pool_shutdown(pool) == NULL);
    CHECK(sleeper.dropped == 1);
    Sleeper late = {reactor, 0, 0, 0, 0};
    CHECK(umilib_platform_runtime_pool_spawner_spawn(spawner, poll_sleeper, drop_sleeper, &late, &handle) == NULL);
    const umilib_ffi_Status* status = umilib_platform_runtime_thread_pool_block_on_thread(handle);
    CHECK(status != NULL && strcmp(status->name, "Cancelled") == 0);
    CHECK(late.polls == 0 && late.dropped == 1);
    umilib_runtime_join_handle_free(handle);

    CHECK(umilib_platform_runtime_pool_spawner_spawn(spawner, NULL, NULL, NULL, &handle) != NULL);
    umilib_platform_runtime_thread_pool_free(pool);
    /* A spawner outliving its pool drops its tasks at once. */
    late.dropped = 0;
    CHECK(umilib_platform_runtime_pool_spawner_spawn(spawner, poll_sleeper, drop_sleeper, &late, &handle) == NULL);
    CHECK(late.dropped == 1);
    umilib_runtime_join_handle_free(handle);
    umilib_platform_runtime_pool_spawner_free(spawner);
    umilib_platform_runtime_pool_spawner_free(NULL);
    umilib_platform_runtime_reactor_free(reactor);
    umilib_platform_runtime_thread_pool_free(NULL);
    umilib_platform_runtime_reactor_free(NULL);
    printf("platform: ok\n");
    return 0;
}
