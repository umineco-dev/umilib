/* Runs a task of C callbacks on an executor of the generated headers, woken through a channel. */
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

typedef struct {
    umilib_runtime_Receiver* receiver;
    size_t received;
    int dropped;
} Consumer;

/* Receives every message; done once the channel is closed. */
static bool poll_consumer(void* context, const umilib_runtime_Waker* waker) {
    Consumer* consumer = context;
    for (;;) {
        bool ready = false;
        umilib_ffi_Buffer message = {0};
        const umilib_ffi_Status* status =
            umilib_runtime_receiver_poll_receive(consumer->receiver, waker, &ready, &message);
        if (status != NULL) {
            return strcmp(status->name, "Closed") == 0;
        }
        if (!ready) {
            return false;
        }
        consumer->received += message.length;
        umilib_ffi_buffer_free(&message);
    }
}

static void drop_consumer(void* context) {
    ((Consumer*)context)->dropped = 1;
}

int main(void) {
    umilib_runtime_Sender* sender = NULL;
    Consumer consumer = {NULL, 0, 0};
    CHECK(umilib_runtime_channel_bounded(2, &sender, &consumer.receiver) == NULL);
    umilib_runtime_LocalExecutor* executor = NULL;
    CHECK(umilib_runtime_local_executor_new(&executor) == NULL);
    umilib_runtime_JoinHandle* handle = NULL;
    CHECK(umilib_runtime_local_executor_spawn(executor, poll_consumer, drop_consumer, &consumer, &handle) == NULL);
    size_t polls = 0;
    for (int round = 0; round < 10; round++) {
        CHECK(umilib_runtime_sender_try_send(sender, (const uint8_t*)"abc", 3) == NULL);
        CHECK(umilib_runtime_local_executor_run_until_idle(executor, &polls) == NULL);
        CHECK(polls == 1);
    }
    CHECK(consumer.received == 30);
    umilib_runtime_sender_free(sender);
    CHECK(umilib_runtime_local_executor_run_until_idle(executor, &polls) == NULL);
    CHECK(consumer.dropped == 1);
    CHECK(umilib_runtime_join_handle_result(handle) == NULL);
    umilib_runtime_join_handle_free(handle);
    umilib_runtime_local_executor_free(executor);
    umilib_runtime_receiver_free(consumer.receiver);
    printf("runtime.c: ok\n");
    return 0;
}
