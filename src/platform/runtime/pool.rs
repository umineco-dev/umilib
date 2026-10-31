use std::cell::Cell;
use std::collections::{TryReserveError, VecDeque};
use std::future::Future;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::pin;
use std::string::String;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{JoinHandle, LocalKey, Thread};
use std::vec::Vec;

use super::ThreadPark;
use crate::runtime::{BoxFuture, Executor, Park, TaskRegistry};

/// The parameters of a [`ThreadPool`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadPoolConfig {
    /// The worker threads; 0 for as many as the system's parallelism.
    pub threads: usize,
    /// The name of the threads, followed by their index.
    pub name: String,
    /// The stack size of the threads, if not std's default.
    pub stack_size: Option<usize>,
}

impl Default for ThreadPoolConfig {
    fn default() -> ThreadPoolConfig {
        ThreadPoolConfig { threads: 0, name: String::from("umilib-worker-"), stack_size: None }
    }
}

/// A task of a [`ThreadPool`]: its future, whether it is queued, and its pool (weakly).
pub struct PoolTask {
    future: Mutex<Option<BoxFuture>>,
    queued: AtomicBool,
    pool: Weak<PoolShared>,
    /// The key of the task in its pool's registry.
    key: AtomicUsize,
}

impl PoolTask {
    /// A task of `future` for the pool `pool`, recorded in its registry (not yet queued).
    pub fn new(future: BoxFuture, pool: &Weak<PoolShared>) -> Arc<PoolTask> {
        let task = Arc::new(PoolTask {
            future: Mutex::new(Some(future)),
            queued: AtomicBool::new(false),
            pool: pool.clone(),
            key: AtomicUsize::new(0),
        });
        if let Some(pool) = pool.upgrade() {
            task.key.store(pool.registry.insert(&task), Ordering::Release);
        }
        task
    }
}

impl PoolTask {
    /// Queues the task unless it is queued; a task of a pool gone or
    /// stopping drops its future (its handle reports it cancelled).
    pub fn schedule(self: &Arc<PoolTask>) {
        if self.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        match self.pool.upgrade() {
            Some(pool) if !pool.stopping.load(Ordering::Acquire) => pool.push(self.clone()),
            _ => {
                let future = self.future.try_lock().ok().and_then(|mut slot| slot.take());
                drop(future);
            }
        }
    }
}

impl Drop for PoolTask {
    /// A task dropped unfinished (no waker of it is left) leaves the registry.
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            pool.registry.remove(*self.key.get_mut(), self);
        }
    }
}

impl Wake for PoolTask {
    fn wake(self: Arc<PoolTask>) {
        self.schedule();
    }

    fn wake_by_ref(self: &Arc<PoolTask>) {
        self.schedule();
    }
}

/// What the threads and handles of a [`ThreadPool`] share.
pub struct PoolShared {
    injector: Mutex<VecDeque<Arc<PoolTask>>>,
    locals: Vec<Mutex<VecDeque<Arc<PoolTask>>>>,
    sleepers: Mutex<Vec<usize>>,
    notified: Vec<AtomicBool>,
    threads: OnceLock<Vec<Thread>>,
    stopping: AtomicBool,
    registry: TaskRegistry<PoolTask>,
}

impl PoolShared {
    /// The pool (its address) and index of the worker running on this thread.
    // The initializer is `const`; clippy reports it anyway on the targets
    // whose thread-locals are emulated (Android).
    #[allow(clippy::missing_const_for_thread_local)]
    pub fn worker() -> &'static LocalKey<Cell<Option<(usize, usize)>>> {
        std::thread_local! {
            static WORKER: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
        }
        &WORKER
    }

    /// Locks `mutex`, recovering it from a panic of another holder (the queues stay consistent).
    pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The address of the pool, which identifies it to its workers.
    pub fn address(self: &Arc<PoolShared>) -> usize {
        Arc::as_ptr(self) as usize
    }

    /// Queues `task`: on the local queue of the worker of this pool running
    /// on this thread, otherwise on the injector; wakes a sleeping worker.
    pub fn push(self: &Arc<PoolShared>, task: Arc<PoolTask>) {
        match PoolShared::worker().get() {
            Some((pool, index)) if pool == self.address() => PoolShared::lock(&self.locals[index]).push_back(task),
            _ => PoolShared::lock(&self.injector).push_back(task),
        }
        self.wake_one();
    }

    /// Unparks one sleeping worker, if any.
    pub fn wake_one(&self) {
        let sleeper = PoolShared::lock(&self.sleepers).pop();
        if let (Some(index), Some(threads)) = (sleeper, self.threads.get()) {
            self.notified[index].store(true, Ordering::Release);
            threads[index].unpark();
        }
    }

    /// The next task for worker `index`: its own, the injector's, or one stolen from another worker.
    pub fn find(&self, index: usize) -> Option<Arc<PoolTask>> {
        if let Some(task) = PoolShared::lock(&self.locals[index]).pop_front() {
            return Some(task);
        }
        if let Some(task) = PoolShared::lock(&self.injector).pop_front() {
            return Some(task);
        }
        let count = self.locals.len();
        (1..count).find_map(|offset| PoolShared::lock(&self.locals[(index + offset) % count]).pop_back())
    }

    /// Whether any queue holds a task.
    pub fn has_work(&self) -> bool {
        !PoolShared::lock(&self.injector).is_empty()
            || self.locals.iter().any(|local| !PoolShared::lock(local).is_empty())
    }

    /// Polls `task` once on this thread; a panic of the task drops it.
    pub fn run(&self, task: Arc<PoolTask>) {
        task.queued.store(false, Ordering::Release);
        let waker = Waker::from(task.clone());
        let mut context = Context::from_waker(&waker);
        let mut slot = PoolShared::lock(&task.future);
        let Some(future) = slot.as_mut() else { return };
        match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(&mut context))) {
            // A task that stopped its own pool (whose shutdown could not take
            // the future it was polling) is dropped once its poll returns.
            Ok(Poll::Pending) if !self.stopping.load(Ordering::Acquire) => {}
            Ok(_) | Err(_) => {
                *slot = None;
                self.registry.remove(task.key.load(Ordering::Acquire), &task);
            }
        }
    }

    /// The loop of worker `index`.
    pub fn work(self: Arc<PoolShared>, index: usize) {
        PoolShared::worker().set(Some((self.address(), index)));
        while !self.stopping.load(Ordering::Acquire) {
            if let Some(task) = self.find(index) {
                self.run(task);
                continue;
            }
            // A notification left from a wake this worker did not sleep for (it
            // was taken off the sleepers while it still saw work) is stale. It
            // is dropped before the worker lists itself again: otherwise the
            // worker would skip its park, list itself a second time, and later
            // wakes would go to it, awake, instead of to a worker asleep. It is
            // not listed here, so no wake can be lost.
            self.notified[index].store(false, Ordering::Release);
            PoolShared::lock(&self.sleepers).push(index);
            if self.has_work() || self.stopping.load(Ordering::Acquire) {
                PoolShared::lock(&self.sleepers).retain(|sleeper| *sleeper != index);
                continue;
            }
            while !self.notified[index].swap(false, Ordering::AcqRel) && !self.stopping.load(Ordering::Acquire) {
                std::thread::park();
            }
        }
        PoolShared::worker().set(None);
    }
}

/// A pool of worker threads that run tasks to completion: each worker has a
/// queue of the tasks woken on it, takes from a shared queue of the tasks
/// spawned or woken elsewhere, and steals from the others when idle; idle
/// workers sleep. A task that panics is dropped (its handle reports it
/// cancelled). Dropping the pool (or [`ThreadPool::shutdown`]) stops the
/// workers and drops every unfinished task.
pub struct ThreadPool {
    shared: Arc<PoolShared>,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl ThreadPool {
    /// A pool of the parameters `config`; fails if a thread cannot be started.
    pub fn new(config: &ThreadPoolConfig) -> io::Result<ThreadPool> {
        let threads = match config.threads {
            0 => std::thread::available_parallelism().map_or(1, usize::from),
            threads => threads,
        };
        // The count may come from a caller (the C ABI): memory for an
        // impossible one is a failure, not an abort.
        let out_of_memory =
            |_: TryReserveError| io::Error::new(io::ErrorKind::OutOfMemory, "no memory for the thread pool's workers");
        let mut locals = Vec::new();
        locals.try_reserve_exact(threads).map_err(out_of_memory)?;
        locals.extend((0..threads).map(|_| Mutex::new(VecDeque::new())));
        let mut notified = Vec::new();
        notified.try_reserve_exact(threads).map_err(out_of_memory)?;
        notified.extend((0..threads).map(|_| AtomicBool::new(false)));
        let mut handles = Vec::new();
        handles.try_reserve_exact(threads).map_err(out_of_memory)?;
        let shared = Arc::new(PoolShared {
            injector: Mutex::new(VecDeque::new()),
            locals,
            sleepers: Mutex::new(Vec::new()),
            notified,
            threads: OnceLock::new(),
            stopping: AtomicBool::new(false),
            registry: TaskRegistry::new(),
        });
        for index in 0..threads {
            let mut builder = std::thread::Builder::new().name(std::format!("{}{index}", config.name));
            if let Some(size) = config.stack_size {
                builder = builder.stack_size(size);
            }
            let worker = shared.clone();
            match builder.spawn(move || worker.work(index)) {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    let pool = ThreadPool { shared, handles: Mutex::new(handles) };
                    pool.shutdown();
                    return Err(error);
                }
            }
        }
        let _ = shared.threads.set(handles.iter().map(|handle| handle.thread().clone()).collect());
        // Workers that went to sleep before the threads were known wake up now if there is work.
        if shared.has_work() {
            (0..threads).for_each(|_| shared.wake_one());
        }
        Ok(ThreadPool { shared, handles: Mutex::new(handles) })
    }

    /// A handle to spawn tasks with (tasks hold one to spawn more).
    pub fn spawner(&self) -> PoolSpawner {
        PoolSpawner { shared: Arc::downgrade(&self.shared) }
    }

    /// The worker threads.
    pub fn threads(&self) -> usize {
        self.shared.locals.len()
    }

    /// Runs `future` to completion on the calling thread (which sleeps when
    /// it is not ready), while the workers run the pool's tasks.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        ThreadPool::block_on_thread(future)
    }

    /// Runs `future` to completion on the calling thread, sleeping when it is not ready.
    pub fn block_on_thread<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let park = Arc::new(ThreadPark::current());
        let waker = Waker::from(Arc::new(ParkWaker { park: park.clone() }));
        let mut context = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
            park.park(None);
        }
    }

    /// Stops the workers (after the tasks they are running) and waits for them; the tasks left are dropped.
    pub fn shutdown(&self) {
        self.shared.stopping.store(true, Ordering::Release);
        let handles: Vec<JoinHandle<()>> = PoolShared::lock(&self.handles).drain(..).collect();
        for handle in &handles {
            handle.thread().unpark();
        }
        let current = std::thread::current().id();
        for handle in handles {
            // A worker that drops the last handle of its own pool cannot join itself.
            if handle.thread().id() != current {
                let _ = handle.join();
            }
        }
        PoolShared::lock(&self.shared.injector).clear();
        self.shared.locals.iter().for_each(|local| PoolShared::lock(local).clear());
        for task in self.shared.registry.drain() {
            let future = task.future.try_lock().ok().and_then(|mut slot| slot.take());
            drop(future);
        }
    }
}

impl Executor for ThreadPool {
    fn spawn_boxed(&self, future: BoxFuture) {
        PoolTask::new(future, &Arc::downgrade(&self.shared)).schedule();
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The waker of [`ThreadPool::block_on_thread`]: it unparks the blocked thread.
pub struct ParkWaker {
    park: Arc<ThreadPark>,
}

impl Wake for ParkWaker {
    fn wake(self: Arc<ParkWaker>) {
        self.park.unpark();
    }

    fn wake_by_ref(self: &Arc<ParkWaker>) {
        self.park.unpark();
    }
}

/// A handle of a pool to spawn tasks from anywhere (tasks hold one to spawn
/// more): it spawns nothing once the pool is dropped.
#[derive(Clone)]
pub struct PoolSpawner {
    shared: Weak<PoolShared>,
}

impl Executor for PoolSpawner {
    fn spawn_boxed(&self, future: BoxFuture) {
        PoolTask::new(future, &self.shared).schedule();
    }
}
