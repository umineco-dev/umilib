/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_RUNTIME_H
#define UMILIB_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The waker of a task: waking it makes its executor poll it again.
 */
typedef struct umilib_runtime_Waker umilib_runtime_Waker;

/**
 * The poll callback of a task: does what it can and returns true once the task is done.
 */
typedef bool (*umilib_runtime_TaskPoll)(void* context, const umilib_runtime_Waker* waker);

/**
 * The drop callback of a task, called once when it is dropped (done or not).
 */
typedef void (*umilib_runtime_TaskDrop)(void* context);

/**
 * An executor that runs its tasks on the thread that drives it.
 */
typedef struct umilib_runtime_LocalExecutor umilib_runtime_LocalExecutor;

/**
 * The handle of a spawned task.
 */
typedef struct umilib_runtime_JoinHandle umilib_runtime_JoinHandle;

/**
 * Timers by deadline, each with a waker.
 */
typedef struct umilib_runtime_TimerQueue umilib_runtime_TimerQueue;

/**
 * A sending side of a bounded channel of byte messages.
 */
typedef struct umilib_runtime_Sender umilib_runtime_Sender;

/**
 * The receiving side of a bounded channel of byte messages.
 */
typedef struct umilib_runtime_Receiver umilib_runtime_Receiver;

/**
 * Wakes the task of `waker` (the waker stays valid).
 */
const umilib_ffi_Status* umilib_runtime_waker_wake(const umilib_runtime_Waker* waker);

/**
 * Writes a copy of `waker` into `out`, to keep beyond the poll it was given to.
 */
const umilib_ffi_Status* umilib_runtime_waker_clone(const umilib_runtime_Waker* waker, umilib_runtime_Waker** out);

/**
 * Releases a waker made by `umilib_runtime_waker_clone`. Does nothing if `waker` is null.
 */
void umilib_runtime_waker_free(umilib_runtime_Waker* waker);

/**
 * Writes a new executor into `out` (it spins when waiting in nothing; the caller drives it with `_run_until_idle`).
 */
const umilib_ffi_Status* umilib_runtime_local_executor_new(umilib_runtime_LocalExecutor** out);

/**
 * Releases an executor (the tasks in its run queue are dropped). Does nothing if `executor` is null.
 */
void umilib_runtime_local_executor_free(umilib_runtime_LocalExecutor* executor);

/**
 * Writes another handle of the same executor into `out`.
 */
const umilib_ffi_Status* umilib_runtime_local_executor_clone(const umilib_runtime_LocalExecutor* executor, umilib_runtime_LocalExecutor** out);

/**
 * Spawns the task of `poll`, `drop` (may be null) and `context`, and writes its handle into `out`.
 */
const umilib_ffi_Status* umilib_runtime_local_executor_spawn(const umilib_runtime_LocalExecutor* executor, umilib_runtime_TaskPoll poll, umilib_runtime_TaskDrop drop, void* context, umilib_runtime_JoinHandle** out);

/**
 * Runs the tasks in the run queue until it is empty and writes the polls made into `polls`.
 */
const umilib_ffi_Status* umilib_runtime_local_executor_run_until_idle(const umilib_runtime_LocalExecutor* executor, size_t* polls);

/**
 * Writes the tasks waiting to run into `out`.
 */
const umilib_ffi_Status* umilib_runtime_local_executor_queued(const umilib_runtime_LocalExecutor* executor, size_t* out);

/**
 * Releases a task handle (the task goes on). Does nothing if `handle` is null.
 */
void umilib_runtime_join_handle_free(umilib_runtime_JoinHandle* handle);

/**
 * Stops the task at its next poll (its drop callback is called).
 */
const umilib_ffi_Status* umilib_runtime_join_handle_abort(const umilib_runtime_JoinHandle* handle);

/**
 * Succeeds once the task finished; fails with `Pending` before, and `Cancelled` if it was aborted or dropped.
 */
const umilib_ffi_Status* umilib_runtime_join_handle_result(umilib_runtime_JoinHandle* handle);

/**
 * Writes a new, empty timer queue into `out`.
 */
const umilib_ffi_Status* umilib_runtime_timer_queue_new(umilib_runtime_TimerQueue** out);

/**
 * Releases a timer queue. Does nothing if `queue` is null.
 */
void umilib_runtime_timer_queue_free(umilib_runtime_TimerQueue* queue);

/**
 * Adds a timer of `deadline` (nanoseconds) whose expiry wakes `waker` (null for none) and writes its key into `key`.
 */
const umilib_ffi_Status* umilib_runtime_timer_queue_insert(umilib_runtime_TimerQueue* queue, uint64_t deadline, const umilib_runtime_Waker* waker, uint64_t* key);

/**
 * Removes the timer `key` and writes whether it was waiting into `removed`.
 */
const umilib_ffi_Status* umilib_runtime_timer_queue_remove(umilib_runtime_TimerQueue* queue, uint64_t key, bool* removed);

/**
 * Writes whether a timer waits into `has` and the earliest deadline into `deadline`.
 */
const umilib_ffi_Status* umilib_runtime_timer_queue_next_deadline(umilib_runtime_TimerQueue* queue, bool* has, uint64_t* deadline);

/**
 * Wakes the timers of a deadline of `now` or earlier and writes how many into `expired`.
 */
const umilib_ffi_Status* umilib_runtime_timer_queue_fire(umilib_runtime_TimerQueue* queue, uint64_t now, size_t* expired);

/**
 * Writes the two sides of a channel of at most `capacity` byte messages into `sender` and `receiver`.
 */
const umilib_ffi_Status* umilib_runtime_channel_bounded(size_t capacity, umilib_runtime_Sender** sender, umilib_runtime_Receiver** receiver);

/**
 * Releases a sender. Does nothing if `sender` is null.
 */
void umilib_runtime_sender_free(umilib_runtime_Sender* sender);

/**
 * Writes another sender of the same channel into `out`.
 */
const umilib_ffi_Status* umilib_runtime_sender_clone(const umilib_runtime_Sender* sender, umilib_runtime_Sender** out);

/**
 * Sends the `length` bytes at `data` as a message; fails with `Full` or `Closed`.
 */
const umilib_ffi_Status* umilib_runtime_sender_try_send(const umilib_runtime_Sender* sender, const uint8_t* data, size_t length);

/**
 * Sends the message if there is room and writes whether it was sent into `sent`; otherwise
 * `waker` is woken when there may be room. Fails with `Closed` once the receiver is gone.
 */
const umilib_ffi_Status* umilib_runtime_sender_poll_send(const umilib_runtime_Sender* sender, const umilib_runtime_Waker* waker, const uint8_t* data, size_t length, bool* sent);

/**
 * Releases a receiver (the channel closes). Does nothing if `receiver` is null.
 */
void umilib_runtime_receiver_free(umilib_runtime_Receiver* receiver);

/**
 * Writes the next message into `out`; fails with `Empty`, or `Closed` once every sender is gone and the channel is empty.
 */
const umilib_ffi_Status* umilib_runtime_receiver_try_receive(umilib_runtime_Receiver* receiver, umilib_ffi_Buffer* out);

/**
 * Writes the next message into `out` and true into `ready` if there is one; otherwise false,
 * and `waker` is woken when one comes. Fails with `Closed` once every sender is gone and the channel is empty.
 */
const umilib_ffi_Status* umilib_runtime_receiver_poll_receive(umilib_runtime_Receiver* receiver, const umilib_runtime_Waker* waker, bool* ready, umilib_ffi_Buffer* out);

/**
 * Closes the channel: sends fail from now on; the messages in it can still be received.
 */
const umilib_ffi_Status* umilib_runtime_receiver_close(umilib_runtime_Receiver* receiver);

/**
 * Writes the messages in the channel into `out`.
 */
const umilib_ffi_Status* umilib_runtime_receiver_len(const umilib_runtime_Receiver* receiver, size_t* out);

#ifdef __cplusplus
}
#endif

#endif
