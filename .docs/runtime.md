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

## Wakers and locks

A waker may run its task inline, or drop it (a `PoolTask` whose pool is
stopping drops its future inside `schedule`), and the task's future may
hold the very object that woke it. Every `SpinLock` of the runtime is
non-reentrant, so a wake under the lock that the woken task's `Drop` takes
again spins forever. The rule is therefore: take the wakers out under the
lock, release it, then wake. The same holds for dropping a waker: the last
waker of a task drops the task, so a waker replaced under a lock is dropped
after it is released.

- The timers had this bug first (`Timer::fire`, see `.docs/platform.md`).
- The bounded channel had it too: `Receiver::try_receive`,
  `Receiver::close` (and `Drop`) and `ReceiveFuture::poll` woke the waiting
  senders under the channel's lock; a sender woken by a stopping pool
  dropped a `Sender` of the same channel and locked it again
  (`senders_are_woken_outside_the_channel`). `ChannelState` now gives the
  wakers out (`take_sender_wakers`) instead of waking them.
- A waiter registers at most one waker per task: `SendFuture` used to push
  a clone on every pending poll, so a sender polled often while the channel
  stayed full (and the C function `umilib_runtime_sender_poll_send`, which
  polls a new future each call) grew the list without bound. It now skips
  a waker that `will_wake` the same task, as `Readiness::register` does.
  `will_wake` is best effort (std may answer false for wakers of one task,
  and Miri does, giving each use of a vtable its own address), so the list
  is bounded only where it answers true; every wake still drains it, so it
  never outlives the channel's being full. The test checks the count only
  outside Miri.

## Timer queue

`TimerQueue` keeps the waiting timers twice: by key (`BTreeMap`, with the
deadline and the waker) and by deadline (`BTreeSet<(Instant, TimerKey)>`),
the two always holding the same timers. It used to order deadlines in a
`BinaryHeap`, which cannot remove an entry: a removed timer stayed in the
heap until its deadline came up, so a task that kept starting and
cancelling sleeps (a timeout around each read) grew the heap without bound,
for ever with a deadline of `Instant::MAX`. Lazy deletion with periodic
rebuilding was rejected: it bounds the growth only by a threshold that is
one more number to choose, where the ordered set removes in logarithmic
time and keeps `next_deadline` exact without mutating.

## Ordering

`LocalTask::queued` is cleared before the task is polled, so a wake during
the poll queues it again. `block_on` polls its future only after a wake
(the flag starts set) and parks only when no task ran and no wake came,
so `Park` implementations may wake spuriously but must remember an
`unpark` made before `park` (`SpinPark` keeps a flag; the test `ThreadPark`
does too, besides `std::thread::park`'s own token).
