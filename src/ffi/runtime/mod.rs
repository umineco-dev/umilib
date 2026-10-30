//! The C ABI of [`crate::runtime`].
//!
//! C has no futures, so a task is a pair of callbacks: `poll(context, waker)`
//! does what it can and returns true once the task is done (keeping the
//! waker, cloned with `umilib_runtime_waker_clone`, to be woken when it can
//! do more), and `drop(context)` is called once when the task is dropped,
//! done or not. A [`LocalExecutor`] runs such tasks on the thread that calls
//! `_run_until_idle`; their contexts must be usable from that thread.
//! Channels carry byte messages; [`TimerQueue`] deadlines are nanoseconds of
//! the caller's clock.

use alloc::vec::Vec;
use core::ffi::c_void;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use crate::ffi::{Buffer, Definition, Function, Module, Parameter, Pointer, Status, Type, Value};
use crate::runtime::{
    Channel, ChannelError, Executor, Instant, JoinHandle, LocalExecutor, Receiver, Sender, TaskError, TimerKey,
    TimerQueue,
};

/// The statuses of this module.
pub struct RuntimeStatus;

impl RuntimeStatus {
    pub const CLOSED: Status = Status::new(c"runtime", c"Closed", c"the other side of the channel is gone");
    pub const FULL: Status = Status::new(c"runtime", c"Full", c"the channel is full");
    pub const EMPTY: Status = Status::new(c"runtime", c"Empty", c"the channel is empty");
    pub const CANCELLED: Status = Status::new(c"runtime", c"Cancelled", c"the task was cancelled");
    pub const PENDING: Status = Status::new(c"runtime", c"Pending", c"the task has not finished");

    pub fn channel(error: ChannelError) -> &'static Status {
        match error {
            ChannelError::Closed => &RuntimeStatus::CLOSED,
            ChannelError::Full => &RuntimeStatus::FULL,
            ChannelError::Empty => &RuntimeStatus::EMPTY,
        }
    }
}

/// The poll callback of a task: `bool poll(void* context, const umilib_runtime_Waker* waker)`.
pub type TaskPoll = Option<unsafe extern "C" fn(context: *mut c_void, waker: *const Waker) -> bool>;
/// The drop callback of a task: `void drop(void* context)` (a type of its
/// own, as other callbacks have the same signature).
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct TaskDrop(pub Option<unsafe extern "C" fn(context: *mut c_void)>);

impl Value for TaskPoll {
    const TYPE: Type = Type::Named("umilib_runtime_TaskPoll");
}

impl Value for TaskDrop {
    const TYPE: Type = Type::Named("umilib_runtime_TaskDrop");
}

impl Value for Waker {
    const TYPE: Type = Type::Named("umilib_runtime_Waker");
}

impl Value for LocalExecutor {
    const TYPE: Type = Type::Named("umilib_runtime_LocalExecutor");
}

impl Value for JoinHandle<()> {
    const TYPE: Type = Type::Named("umilib_runtime_JoinHandle");
}

impl Value for TimerQueue {
    const TYPE: Type = Type::Named("umilib_runtime_TimerQueue");
}

impl Value for Sender<Vec<u8>> {
    const TYPE: Type = Type::Named("umilib_runtime_Sender");
}

impl Value for Receiver<Vec<u8>> {
    const TYPE: Type = Type::Named("umilib_runtime_Receiver");
}

/// A task of C callbacks, as a future.
pub struct CallbackTask {
    poll: unsafe extern "C" fn(context: *mut c_void, waker: *const Waker) -> bool,
    drop: TaskDrop,
    context: *mut c_void,
}

impl CallbackTask {
    /// The task of `poll`, `drop` and `context`.
    ///
    /// # Safety
    /// `poll` and `drop` may be called with `context` (from the threads of
    /// the executor that runs the task, one at a time) until the drop
    /// callback is called, once; the caller keeps them valid until then.
    pub unsafe fn new(
        poll: unsafe extern "C" fn(context: *mut c_void, waker: *const Waker) -> bool,
        drop: TaskDrop,
        context: *mut c_void,
    ) -> CallbackTask {
        CallbackTask { poll, drop, context }
    }
}

// SAFETY: the caller of a spawn promises that the context may be used from
// the threads that run the executor (one at a time: a task is never polled
// by two threads at once).
unsafe impl Send for CallbackTask {}

impl Future for CallbackTask {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        // SAFETY: the callback and its context are the caller's, valid until the drop callback.
        if unsafe { (self.poll)(self.context, context.waker()) } { Poll::Ready(()) } else { Poll::Pending }
    }
}

impl Drop for CallbackTask {
    fn drop(&mut self) {
        if let TaskDrop(Some(drop)) = self.drop {
            // SAFETY: as above; the drop callback is called once.
            unsafe { drop(self.context) }
        }
    }
}

crate::ffi_functions! {
    const FUNCTIONS;

    /// Wakes the task of `waker` (the waker stays valid).
    pub unsafe extern "C" fn umilib_runtime_waker_wake(waker: *const Waker) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid waker.
            unsafe { Pointer::reference(waker) }?.wake_by_ref();
            Ok(())
        })())
    }

    /// Writes a copy of `waker` into `out`, to keep beyond the poll it was given to.
    pub unsafe extern "C" fn umilib_runtime_waker_clone(waker: *const Waker, out: *mut *mut Waker) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid waker and a writable pointer.
            let waker = unsafe { Pointer::reference(waker) }?;
            unsafe { Pointer::write_handle(out, waker.clone()) }
        })())
    }

    /// Releases a waker made by `umilib_runtime_waker_clone`. Does nothing if `waker` is null.
    pub unsafe extern "C" fn umilib_runtime_waker_free(waker: *mut Waker) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(waker) }
    }

    /// Writes a new executor into `out` (it spins when waiting in nothing; the caller drives it with `_run_until_idle`).
    pub unsafe extern "C" fn umilib_runtime_local_executor_new(out: *mut *mut LocalExecutor) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, LocalExecutor::new()) })
    }

    /// Releases an executor (the tasks in its run queue are dropped). Does nothing if `executor` is null.
    pub unsafe extern "C" fn umilib_runtime_local_executor_free(executor: *mut LocalExecutor) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(executor) }
    }

    /// Writes another handle of the same executor into `out`.
    pub unsafe extern "C" fn umilib_runtime_local_executor_clone(executor: *const LocalExecutor, out: *mut *mut LocalExecutor) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let executor = unsafe { Pointer::reference(executor) }?;
            unsafe { Pointer::write_handle(out, executor.clone()) }
        })())
    }

    /// Spawns the task of `poll`, `drop` (may be null) and `context`, and writes its handle into `out`.
    pub unsafe extern "C" fn umilib_runtime_local_executor_spawn(executor: *const LocalExecutor, poll: TaskPoll, drop: TaskDrop, context: *mut c_void, out: *mut *mut JoinHandle<()>) -> *const Status {
        Status::from_result((|| {
            let poll = poll.ok_or(&Status::INVALID_ARGUMENT)?;
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let executor = unsafe { Pointer::reference(executor) }?;
            // SAFETY: the caller of this function promises what `CallbackTask::new` requires.
            let handle = executor.spawn(unsafe { CallbackTask::new(poll, drop, context) });
            unsafe { Pointer::write_handle(out, handle) }
        })())
    }

    /// Runs the tasks in the run queue until it is empty and writes the polls made into `polls`.
    pub unsafe extern "C" fn umilib_runtime_local_executor_run_until_idle(executor: *const LocalExecutor, polls: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let executor = unsafe { Pointer::reference(executor) }?;
            let count = executor.run_until_idle();
            unsafe { Pointer::write(polls, count) }
        })())
    }

    /// Writes the tasks waiting to run into `out`.
    pub unsafe extern "C" fn umilib_runtime_local_executor_queued(executor: *const LocalExecutor, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let executor = unsafe { Pointer::reference(executor) }?;
            unsafe { Pointer::write(out, executor.queued()) }
        })())
    }

    /// Releases a task handle (the task goes on). Does nothing if `handle` is null.
    pub unsafe extern "C" fn umilib_runtime_join_handle_free(handle: *mut JoinHandle<()>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(handle) }
    }

    /// Stops the task at its next poll (its drop callback is called).
    pub unsafe extern "C" fn umilib_runtime_join_handle_abort(handle: *const JoinHandle<()>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference(handle) }?.abort();
            Ok(())
        })())
    }

    /// Succeeds once the task finished; fails with `Pending` before, and `Cancelled` if it was aborted or dropped.
    pub unsafe extern "C" fn umilib_runtime_join_handle_result(handle: *mut JoinHandle<()>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let handle = unsafe { Pointer::reference_mut(handle) }?;
            match handle.try_take() {
                None => Err(&RuntimeStatus::PENDING),
                Some(Ok(())) => Ok(()),
                Some(Err(TaskError::Cancelled)) => Err(&RuntimeStatus::CANCELLED),
            }
        })())
    }

    /// Writes a new, empty timer queue into `out`.
    pub unsafe extern "C" fn umilib_runtime_timer_queue_new(out: *mut *mut TimerQueue) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, TimerQueue::new()) })
    }

    /// Releases a timer queue. Does nothing if `queue` is null.
    pub unsafe extern "C" fn umilib_runtime_timer_queue_free(queue: *mut TimerQueue) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(queue) }
    }

    /// Adds a timer of `deadline` (nanoseconds) whose expiry wakes `waker` (null for none) and writes its key into `key`.
    pub unsafe extern "C" fn umilib_runtime_timer_queue_insert(queue: *mut TimerQueue, deadline: u64, waker: *const Waker, key: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, null or a valid waker, and a writable pointer.
            let queue = unsafe { Pointer::reference_mut(queue) }?;
            let waker = if waker.is_null() { None } else { Some(unsafe { Pointer::reference(waker) }?.clone()) };
            Pointer::check_range(key, 1)?;
            let inserted = queue.insert(Instant::from_nanos(deadline), waker);
            unsafe { Pointer::write(key, inserted.value()) }
        })())
    }

    /// Removes the timer `key` and writes whether it was waiting into `removed`.
    pub unsafe extern "C" fn umilib_runtime_timer_queue_remove(queue: *mut TimerQueue, key: u64, removed: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let queue = unsafe { Pointer::reference_mut(queue) }?;
            let key = TimerKey::from_value(key);
            unsafe { Pointer::write(removed, queue.remove(key)) }
        })())
    }

    /// Writes whether a timer waits into `has` and the earliest deadline into `deadline`.
    pub unsafe extern "C" fn umilib_runtime_timer_queue_next_deadline(queue: *mut TimerQueue, has: *mut bool, deadline: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let queue = unsafe { Pointer::reference_mut(queue) }?;
            let next = queue.next_deadline();
            unsafe { Pointer::write(has, next.is_some()) }?;
            unsafe { Pointer::write(deadline, next.map_or(0, Instant::as_nanos)) }
        })())
    }

    /// Wakes the timers of a deadline of `now` or earlier and writes how many into `expired`.
    pub unsafe extern "C" fn umilib_runtime_timer_queue_fire(queue: *mut TimerQueue, now: u64, expired: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let queue = unsafe { Pointer::reference_mut(queue) }?;
            Pointer::check_range(expired, 1)?;
            let count = queue.fire(Instant::from_nanos(now));
            unsafe { Pointer::write(expired, count) }
        })())
    }

    /// Writes the two sides of a channel of at most `capacity` byte messages into `sender` and `receiver`.
    pub unsafe extern "C" fn umilib_runtime_channel_bounded(capacity: usize, sender: *mut *mut Sender<Vec<u8>>, receiver: *mut *mut Receiver<Vec<u8>>) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(sender, 1)?;
            Pointer::check_range(receiver, 1)?;
            let (send, receive) = Channel::bounded::<Vec<u8>>(capacity);
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write_handle(sender, send) }?;
            unsafe { Pointer::write_handle(receiver, receive) }
        })())
    }

    /// Releases a sender. Does nothing if `sender` is null.
    pub unsafe extern "C" fn umilib_runtime_sender_free(sender: *mut Sender<Vec<u8>>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(sender) }
    }

    /// Writes another sender of the same channel into `out`.
    pub unsafe extern "C" fn umilib_runtime_sender_clone(sender: *const Sender<Vec<u8>>, out: *mut *mut Sender<Vec<u8>>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let sender = unsafe { Pointer::reference(sender) }?;
            unsafe { Pointer::write_handle(out, sender.clone()) }
        })())
    }

    /// Sends the `length` bytes at `data` as a message; fails with `Full` or `Closed`.
    pub unsafe extern "C" fn umilib_runtime_sender_try_send(sender: *const Sender<Vec<u8>>, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let sender = unsafe { Pointer::reference(sender) }?;
            let message = unsafe { Pointer::slice(data, length) }?.to_vec();
            sender.try_send(message).map_err(|error| RuntimeStatus::channel(error.error))
        })())
    }

    /// Sends the message if there is room and writes whether it was sent into `sent`; otherwise
    /// `waker` is woken when there may be room. Fails with `Closed` once the receiver is gone.
    pub unsafe extern "C" fn umilib_runtime_sender_poll_send(sender: *const Sender<Vec<u8>>, waker: *const Waker, data: *const u8, length: usize, sent: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles, readable bytes and a writable pointer.
            let sender = unsafe { Pointer::reference(sender) }?;
            let waker = unsafe { Pointer::reference(waker) }?;
            let message = unsafe { Pointer::slice(data, length) }?.to_vec();
            Pointer::check_range(sent, 1)?;
            let mut future = sender.send(message);
            let result = Pin::new(&mut future).poll(&mut Context::from_waker(waker));
            let done = match result {
                Poll::Ready(Ok(())) => true,
                Poll::Ready(Err(error)) => return Err(RuntimeStatus::channel(error.error)),
                Poll::Pending => false,
            };
            unsafe { Pointer::write(sent, done) }
        })())
    }

    /// Releases a receiver (the channel closes). Does nothing if `receiver` is null.
    pub unsafe extern "C" fn umilib_runtime_receiver_free(receiver: *mut Receiver<Vec<u8>>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(receiver) }
    }

    /// Writes the next message into `out`; fails with `Empty`, or `Closed` once every sender is gone and the channel is empty.
    pub unsafe extern "C" fn umilib_runtime_receiver_try_receive(receiver: *mut Receiver<Vec<u8>>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let receiver = unsafe { Pointer::reference_mut(receiver) }?;
            Pointer::check_range(out, 1)?;
            let message = receiver.try_receive().map_err(RuntimeStatus::channel)?;
            unsafe { Pointer::write(out, Buffer::from_vec(message)) }
        })())
    }

    /// Writes the next message into `out` and true into `ready` if there is one; otherwise false,
    /// and `waker` is woken when one comes. Fails with `Closed` once every sender is gone and the channel is empty.
    pub unsafe extern "C" fn umilib_runtime_receiver_poll_receive(receiver: *mut Receiver<Vec<u8>>, waker: *const Waker, ready: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and writable pointers.
            let receiver = unsafe { Pointer::reference_mut(receiver) }?;
            let waker = unsafe { Pointer::reference(waker) }?;
            Pointer::check_range(ready, 1)?;
            Pointer::check_range(out, 1)?;
            let mut future = receiver.receive();
            match Pin::new(&mut future).poll(&mut Context::from_waker(waker)) {
                Poll::Ready(Some(message)) => {
                    unsafe { Pointer::write(out, Buffer::from_vec(message)) }?;
                    unsafe { Pointer::write(ready, true) }
                }
                Poll::Ready(None) => Err(&RuntimeStatus::CLOSED),
                Poll::Pending => unsafe { Pointer::write(ready, false) },
            }
        })())
    }

    /// Closes the channel: sends fail from now on; the messages in it can still be received.
    pub unsafe extern "C" fn umilib_runtime_receiver_close(receiver: *mut Receiver<Vec<u8>>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(receiver) }?.close();
            Ok(())
        })())
    }

    /// Writes the messages in the channel into `out`.
    pub unsafe extern "C" fn umilib_runtime_receiver_len(receiver: *const Receiver<Vec<u8>>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let receiver = unsafe { Pointer::reference(receiver) }?;
            unsafe { Pointer::write(out, receiver.len()) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "runtime",
    definitions: &[
        Definition::Opaque {
            name: "umilib_runtime_Waker",
            documentation: " The waker of a task: waking it makes its executor poll it again.",
        },
        Definition::Callback {
            name: "umilib_runtime_TaskPoll",
            documentation: " The poll callback of a task: does what it can and returns true once the task is done.",
            parameters: &[
                Parameter { name: "context", value: <*mut c_void as Value>::TYPE },
                Parameter { name: "waker", value: <*const Waker as Value>::TYPE },
            ],
            returns: Type::Bool,
        },
        Definition::Callback {
            name: "umilib_runtime_TaskDrop",
            documentation: " The drop callback of a task, called once when it is dropped (done or not).",
            parameters: &[Parameter { name: "context", value: <*mut c_void as Value>::TYPE }],
            returns: Type::Void,
        },
        Definition::Opaque {
            name: "umilib_runtime_LocalExecutor",
            documentation: " An executor that runs its tasks on the thread that drives it.",
        },
        Definition::Opaque { name: "umilib_runtime_JoinHandle", documentation: " The handle of a spawned task." },
        Definition::Opaque {
            name: "umilib_runtime_TimerQueue",
            documentation: " Timers by deadline, each with a waker.",
        },
        Definition::Opaque {
            name: "umilib_runtime_Sender",
            documentation: " A sending side of a bounded channel of byte messages.",
        },
        Definition::Opaque {
            name: "umilib_runtime_Receiver",
            documentation: " The receiving side of a bounded channel of byte messages.",
        },
    ],
    functions: &Function::concat::<{ FUNCTIONS.len() }>(&[FUNCTIONS]),
    modules: &[],
};
