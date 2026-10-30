# `umilib::runtime`

The asynchronous runtime, without `std`. Feature: `runtime`. It runs
futures (`async` code) on executors, lets tasks wait on channels and timers,
and defines the I/O traits the protocols are written against. It needs a
target with atomic pointer operations; it uses only `core` and `alloc`. The
platform runtime (`platform-runtime`) adds threads, the operating system's
event loop and clocks.

## Executors and tasks

```rust
use umilib::runtime::{Executor, LocalExecutor};

let executor = LocalExecutor::new();
let handle = executor.spawn(async { 1 + 1 });     // a JoinHandle<u32>
let result = executor.block_on(handle);           // Ok(2)
```

- `Executor` is what runs futures: `spawn(future)` returns a `JoinHandle`,
  a future of `Result<output, TaskError>`. `handle.abort()` stops the task
  at its next poll (its future is dropped) and the handle gives
  `TaskError::Cancelled`, as it does for a task dropped unfinished.
  Dropping a handle detaches the task.
- `LocalExecutor` runs its tasks on the thread that calls
  `run_until_idle()` (which polls the queued tasks until none is left) or
  `block_on(future)` (which runs `future` to completion, running the tasks
  meanwhile). Tasks are `Send` and may be woken from any thread. Dropping
  the last clone of an executor drops every unfinished task, queued or
  waiting (its future is dropped and its handle gives
  `TaskError::Cancelled`); a task woken after its executor is gone is
  dropped.
- When nothing is ready, `block_on` waits with the executor's `Park`
  (`LocalExecutor::with_park`): `SpinPark` (the default) spins, for
  environments without threads; the platform runtime provides one that
  sleeps. `TimerPark` wraps a `Park` so that waiting stops at the next
  timer deadline and expired timers are woken.

## Channels

- `Channel::bounded::<T>(capacity)`: any number of `Sender`s (clone them),
  one `Receiver`, at most `capacity` values in flight. `send(value).await`
  waits for room; `try_send` fails with `ChannelError::Full` instead (both
  give the value back in `SendError` when the receiver is gone:
  `ChannelError::Closed`). `receive().await` gives `None` once every
  sender is gone and the channel is drained; `try_receive` gives
  `ChannelError::Empty` or `Closed`. `Receiver::close` refuses further
  sends but keeps the values in the channel.
- `Channel::oneshot::<T>()`: one value. `OneshotSender::send` gives the
  value back if the receiver is gone; the `OneshotReceiver` is a future of
  `Result<T, ChannelError>` (`Closed` if the sender is dropped without sending).

## Time

- `Instant` (nanoseconds of a monotonic clock, saturating arithmetic with
  `core::time::Duration`) and `Clock` (`now()`), which the platform (or a
  test) provides.
- `TimerQueue`: timers by deadline, each with a waker; `next_deadline()`
  and `fire(now)` (wakes the expired timers) are what a driver calls.
- `Timer`: a timer queue and its clock, shared: `sleep(duration)`,
  `sleep_until(deadline)` and `timeout(duration, future)` (which gives
  `Err(Elapsed)` when time runs out) are futures that wait on it; `fire()`
  wakes the expired timers and returns the next deadline.

## I/O

- `IOError` (`IOErrorKind` and the operating system's error code) and
  `SocketAddress` (IPv4 or IPv6 with port, flow and scope).
- `AsyncRead`, `AsyncWrite` (with `write_all`, `flush`, `shutdown`) and
  `AsyncDatagram` (`send_to`, `receive_from`) take and give back owned
  buffers, as completion-based systems (IOCP, io_uring) need: a read fills
  the spare capacity of the `Vec` it is given and returns it with the
  count (0 at the end of the stream).
- `DuplexStream::pair(capacity)`: two connected in-memory ends, at most
  `capacity` bytes in flight each way, for tests and in-process pipelines.
  Dropping an end makes the other read the end of the stream and fail
  writes with `BrokenPipe`.

## Futures and locks

`Join::new(a, b)` (both outputs), `Select::new(a, b)` (the first to finish,
as `Either`), `JoinAll::new(futures)` and `YieldNow::new()` (lets other
tasks run). `SpinLock` and `AtomicWaker` are the synchronization the
runtime is built on, for short critical sections where no operating system
lock exists.

## C and Python

C has no futures: a task is a pair of callbacks, `bool poll(void* context,
const umilib_runtime_Waker* waker)` (returns true once done, keeping a
clone of the waker, `umilib_runtime_waker_clone`, to be woken) and `void
drop(void* context)` (called once when the task is dropped).
`umilib_runtime_local_executor_spawn` runs one on a `LocalExecutor` driven
by `_run_until_idle`; `umilib_runtime_join_handle_result` reports `Pending`
or `Cancelled`. Timer queues (deadlines in nanoseconds of the caller's
clock) and channels of byte messages (`_try_send`, `_poll_send`,
`_try_receive`, `_poll_receive` with a waker) are exported too. Python
mirrors them: a task is a function `poll(waker) -> bool`; a task spawns
others through a clone of the executor (a Python handle is not used again
from inside a call on it); a poll function that raises ends its task and
`run_until_idle` raises the exception. Errors are `RuntimeStatusError`
(`Closed`, `Full`, `Empty`, `Cancelled`, `Pending`).
