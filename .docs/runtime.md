# Runtime internals

How `umilib::runtime` is built. The user-facing description is in
[docs/runtime.md](../docs/runtime.md).

## Wakers without `unsafe`

Wakers are made with `alloc::task::Wake` (`Waker::from(Arc<T>)`), so the
runtime has no hand-written waker vtable. The only `unsafe` code is the
`SpinLock` (its `UnsafeCell` and `Send`/`Sync` implementations).

## Reference cycles

A task is easily kept alive by itself: its future holds wakers of other
tasks, a channel holds the waker of the task waiting on it, and so on.
The runtime avoids the cycles it would create itself:

- `LocalTask` holds its run queue weakly. Queue → task is the only strong
  edge, so dropping the executor drops the queued tasks; a task woken
  after its executor is gone drops its future instead of being queued.
- A task waiting on something that never wakes it (a channel whose other
  end is held by another waiting task, a timer that never fires) is in no
  queue, so the queue cannot drop it. Every executor records its
  unfinished tasks weakly in a `TaskRegistry` (a slot per task, the free
  slots reused), and dropping the executor (or `ThreadPool::shutdown`)
  drops the futures of those still alive. Without it, such tasks and
  everything their futures hold leak, and their handles never finish.
- `TaskState` keeps the task's waker (to wake it when its `JoinHandle`
  aborts it) only while the handle exists: dropping the handle clears the
  slot, and a task polled afterwards does not store its waker again
  (`TaskFuture::poll` checks the handle flag before and after registering,
  so a concurrent drop cannot leave a waker behind).

Miri runs the runtime tests (`cargo +nightly miri test --features runtime
--test runtime`) and reports leaked memory, which is how these cycles show.

## Ordering

`LocalTask::queued` is cleared before the task is polled, so a wake during
the poll queues it again. `block_on` polls its future only after a wake
(the flag starts set) and parks only when no task ran and no wake came,
so `Park` implementations may wake spuriously but must remember an
`unpark` made before `park` (`SpinPark` keeps a flag; the test `ThreadPark`
does too, besides `std::thread::park`'s own token).
