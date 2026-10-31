//! The C ABI of [`crate::platform::runtime`]:
//! - a thread pool that runs the callback tasks of [`crate::ffi::runtime`]
//!   on its threads (a task's context must be usable from any of them, one
//!   at a time);
//! - the system's monotonic clock;
//! - a reactor, whose timer wakes a task's waker at a deadline.
//!
//! The asynchronous sockets and the supervisor have no C ABI yet. On a
//! system without the platform runtime, the functions fail with
//! `Unsupported` (the header is the same everywhere).

use core::ffi::c_void;
use core::task::Waker;

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
use super::native::NativeStatus;
use crate::ffi::runtime::{RuntimeStatus, TaskDrop, TaskPoll};
use crate::ffi::{Definition, Module, Pointer, Status, Type, Value};
use crate::runtime::JoinHandle;

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
pub use crate::platform::runtime::{PoolSpawner, Reactor, ThreadPool};

/// The thread pool where the system has no platform runtime: none is ever made.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
pub enum ThreadPool {}

/// The spawner where the system has no platform runtime: none is ever made.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
pub enum PoolSpawner {}

/// The reactor where the system has no platform runtime: none is ever made.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
pub enum Reactor {}

impl Value for ThreadPool {
    const TYPE: Type = Type::Named("umilib_platform_runtime_ThreadPool");
}

impl Value for PoolSpawner {
    const TYPE: Type = Type::Named("umilib_platform_runtime_PoolSpawner");
}

impl Value for Reactor {
    const TYPE: Type = Type::Named("umilib_platform_runtime_Reactor");
}

/// The statuses of this module.
pub struct PlatformRuntimeStatus;

impl PlatformRuntimeStatus {
    pub const THREAD: Status = Status::new(c"platform", c"Thread", c"a thread could not be started");
}

crate::ffi_functions! {
    const FUNCTIONS;

    /// Writes a new pool of `threads` threads (0 for as many as the system's parallelism) into `out`.
    pub unsafe extern "C" fn umilib_platform_runtime_thread_pool_new(threads: usize, out: *mut *mut ThreadPool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(out, 1)?;
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
            {
                use crate::platform::runtime::ThreadPoolConfig;
                let config = ThreadPoolConfig { threads, ..ThreadPoolConfig::default() };
                let pool = ThreadPool::new(&config).map_err(|error| match error.kind() {
                    std::io::ErrorKind::OutOfMemory => &Status::INVALID_ARGUMENT,
                    _ => &PlatformRuntimeStatus::THREAD,
                })?;
                // SAFETY: the caller passes a writable pointer.
                unsafe { Pointer::write_handle(out, pool) }
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
            {
                let _ = threads;
                Err(&NativeStatus::UNSUPPORTED)
            }
        })())
    }

    /// Releases a pool: stops its threads (after the polls they are making) and drops the tasks
    /// left, calling their drop callbacks. Does nothing if `pool` is null.
    pub unsafe extern "C" fn umilib_platform_runtime_thread_pool_free(pool: *mut ThreadPool) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(pool) }
    }

    /// Writes the threads of the pool into `out`.
    pub unsafe extern "C" fn umilib_platform_runtime_thread_pool_threads(pool: *const ThreadPool, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let pool = unsafe { Pointer::reference(pool) }?;
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
            {
                // SAFETY: the caller passes a writable pointer.
                unsafe { Pointer::write(out, pool.threads()) }
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
            {
                let _ = out;
                match *pool {}
            }
        })())
    }

    /// Writes a spawner of the pool into `out`: tasks keep one to spawn more (spawning through
    /// the pool itself from a task would wait for the pool's users in some bindings). Once the
    /// pool is released or stopped, the tasks it spawns are dropped at once.
    pub unsafe extern "C" fn umilib_platform_runtime_thread_pool_spawner(pool: *const ThreadPool, out: *mut *mut PoolSpawner) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let pool = unsafe { Pointer::reference(pool) }?;
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
            {
                // SAFETY: the caller passes a writable pointer.
                unsafe { Pointer::write_handle(out, pool.spawner()) }
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
            {
                let _ = out;
                match *pool {}
            }
        })())
    }

    /// Releases a spawner. Does nothing if `spawner` is null.
    pub unsafe extern "C" fn umilib_platform_runtime_pool_spawner_free(spawner: *mut PoolSpawner) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(spawner) }
    }

    /// Spawns the task of `poll`, `drop` (may be null) and `context` on the pool of the spawner,
    /// and writes its handle into `out`. The context must be usable from any thread of the pool.
    pub unsafe extern "C" fn umilib_platform_runtime_pool_spawner_spawn(spawner: *const PoolSpawner, poll: TaskPoll, drop: TaskDrop, context: *mut c_void, out: *mut *mut JoinHandle<()>) -> *const Status {
        Status::from_result((|| {
            let poll = poll.ok_or(&Status::INVALID_ARGUMENT)?;
            Pointer::check_range(out, 1)?;
            // SAFETY: the caller passes a valid handle.
            let spawner = unsafe { Pointer::reference(spawner) }?;
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
            {
                use crate::ffi::runtime::CallbackTask;
                use crate::runtime::Executor;
                // SAFETY: the caller of this function promises what `CallbackTask::new` requires.
                let handle = spawner.spawn(unsafe { CallbackTask::new(poll, drop, context) });
                // SAFETY: the caller passes a writable pointer.
                unsafe { Pointer::write_handle(out, handle) }
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
            {
                let _ = (poll, drop, context);
                match *spawner {}
            }
        })())
    }

    /// Blocks the calling thread until the task of `handle` is done; fails with `Cancelled` if it
    /// was aborted or dropped (its pool stopped). It needs no pool: any thread may wait.
    pub unsafe extern "C" fn umilib_platform_runtime_thread_pool_block_on_thread(handle: *mut JoinHandle<()>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let handle = unsafe { Pointer::reference_mut(handle) }?;
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
            {
                ThreadPool::block_on_thread(handle).map_err(|_| &RuntimeStatus::CANCELLED)
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
            {
                let _ = (handle, &RuntimeStatus::CANCELLED);
                Err(&NativeStatus::UNSUPPORTED)
            }
        })())
    }

    /// Stops the threads of the pool (after the polls they are making) and drops the tasks left,
    /// calling their drop callbacks; tasks spawned afterwards are dropped at once.
    pub unsafe extern "C" fn umilib_platform_runtime_thread_pool_shutdown(pool: *const ThreadPool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let pool = unsafe { Pointer::reference(pool) }?;
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
            {
                pool.shutdown();
                Ok(())
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
            {
                match *pool {}
            }
        })())
    }

    /// Writes the nanoseconds of the system's monotonic clock since the process first read it into `out`.
    pub unsafe extern "C" fn umilib_platform_runtime_monotonic_clock_now(out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(out, 1)?;
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
            {
                use crate::platform::runtime::MonotonicClock;
                use crate::runtime::Clock;
                // SAFETY: the caller passes a writable pointer.
                unsafe { Pointer::write(out, MonotonicClock::new().now().as_nanos()) }
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
            {
                Err(&NativeStatus::UNSUPPORTED)
            }
        })())
    }

    /// Writes a new reactor (its thread started) into `out`.
    pub unsafe extern "C" fn umilib_platform_runtime_reactor_new(out: *mut *mut Reactor) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(out, 1)?;
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
            {
                use crate::platform::runtime::ReactorConfig;
                let reactor = Reactor::new(&ReactorConfig::default()).map_err(|_| &PlatformRuntimeStatus::THREAD)?;
                // SAFETY: the caller passes a writable pointer.
                unsafe { Pointer::write_handle(out, reactor) }
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
            {
                Err(&NativeStatus::UNSUPPORTED)
            }
        })())
    }

    /// Releases a reactor (its thread stops once nothing uses it). Does nothing if `reactor` is null.
    pub unsafe extern "C" fn umilib_platform_runtime_reactor_free(reactor: *mut Reactor) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(reactor) }
    }

    /// Writes the nanoseconds of the reactor's clock (the monotonic clock) into `out`.
    pub unsafe extern "C" fn umilib_platform_runtime_reactor_now(reactor: *const Reactor, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let reactor = unsafe { Pointer::reference(reactor) }?;
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
            {
                // SAFETY: the caller passes a writable pointer.
                unsafe { Pointer::write(out, reactor.timer().now().as_nanos()) }
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
            {
                let _ = out;
                match *reactor {}
            }
        })())
    }

    /// Wakes `waker` once the reactor's clock reaches `deadline` (nanoseconds; at once if it has)
    /// and writes the key of the timer into `key`: a task that stops waiting removes it.
    pub unsafe extern "C" fn umilib_platform_runtime_reactor_wake_at(reactor: *const Reactor, deadline: u64, waker: *const Waker, key: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let reactor = unsafe { Pointer::reference(reactor) }?;
            let waker = unsafe { Pointer::reference(waker) }?;
            Pointer::check_range(key, 1)?;
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
            {
                use crate::runtime::Instant;
                let inserted = reactor.timer().insert(Instant::from_nanos(deadline), Some(waker.clone()));
                // SAFETY: the caller passes a writable pointer.
                unsafe { Pointer::write(key, inserted.value()) }
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
            {
                let _ = (deadline, waker, key);
                match *reactor {}
            }
        })())
    }

    /// Removes the timer `key` of `_wake_at` and writes whether it was waiting into `removed`.
    pub unsafe extern "C" fn umilib_platform_runtime_reactor_remove(reactor: *const Reactor, key: u64, removed: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let reactor = unsafe { Pointer::reference(reactor) }?;
            Pointer::check_range(removed, 1)?;
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
            {
                use crate::runtime::TimerKey;
                let was = reactor.timer().queue().lock().remove(TimerKey::from_value(key));
                // SAFETY: the caller passes a writable pointer.
                unsafe { Pointer::write(removed, was) }
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
            {
                let _ = (key, removed);
                match *reactor {}
            }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "runtime",
    definitions: &[
        Definition::Opaque {
            name: "umilib_platform_runtime_ThreadPool",
            documentation: " A pool of threads that run callback tasks.",
        },
        Definition::Opaque {
            name: "umilib_platform_runtime_PoolSpawner",
            documentation: " A handle that spawns tasks on a thread pool while it exists.",
        },
        Definition::Opaque {
            name: "umilib_platform_runtime_Reactor",
            documentation: " A thread that waits on the system's I/O and wakes timers.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
