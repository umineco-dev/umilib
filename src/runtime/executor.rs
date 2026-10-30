use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::task::Wake;
use core::future::Future;
use core::pin::{Pin, pin};
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

use super::sync::SpinLock;
use super::{JoinHandle, Park, SpinPark, TaskFuture, TaskRegistry};

/// A future an executor runs: boxed, sendable, of no output.
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Something that runs futures to completion.
pub trait Executor {
    /// Runs `future` to completion, on the executor's own time.
    fn spawn_boxed(&self, future: BoxFuture);

    /// Runs `future` and returns the handle of its output.
    fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
        Self: Sized,
    {
        let (task, handle) = TaskFuture::new(future);
        self.spawn_boxed(Box::pin(task));
        handle
    }
}

/// A task of a [`LocalExecutor`]: its future, whether it is in the run
/// queue, and the queue (weakly: a task woken after its executor is gone is
/// not run, and its future is dropped).
pub struct LocalTask {
    future: SpinLock<Option<BoxFuture>>,
    queued: AtomicBool,
    queue: Weak<LocalQueue>,
    /// The key of the task in its executor's registry.
    key: core::sync::atomic::AtomicUsize,
}

impl LocalTask {
    /// Puts the task in the run queue unless it is there; a task woken after
    /// its executor is gone drops its future instead (its handle reports it cancelled).
    pub fn schedule(self: &Arc<LocalTask>) {
        if self.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        match self.queue.upgrade() {
            Some(queue) => queue.push(self.clone()),
            None => {
                let future = self.future.try_lock().and_then(|mut slot| slot.take());
                drop(future);
            }
        }
    }
}

impl Drop for LocalTask {
    /// A task dropped unfinished (no waker of it is left) leaves the registry.
    fn drop(&mut self) {
        if let Some(queue) = self.queue.upgrade() {
            queue.registry.remove(*self.key.get_mut(), self);
        }
    }
}

impl Wake for LocalTask {
    fn wake(self: Arc<LocalTask>) {
        self.schedule();
    }

    fn wake_by_ref(self: &Arc<LocalTask>) {
        self.schedule();
    }
}

/// The run queue of a [`LocalExecutor`], its unfinished tasks and the
/// parker it unparks. Dropped with the last executor, it cancels every
/// unfinished task.
pub struct LocalQueue {
    tasks: SpinLock<VecDeque<Arc<LocalTask>>>,
    registry: TaskRegistry<LocalTask>,
    park: Arc<dyn Park + Send + Sync>,
}

impl Drop for LocalQueue {
    fn drop(&mut self) {
        self.tasks.lock().clear();
        for task in self.registry.drain() {
            let future = task.future.try_lock().and_then(|mut slot| slot.take());
            drop(future);
        }
    }
}

impl LocalQueue {
    pub fn push(&self, task: Arc<LocalTask>) {
        self.tasks.lock().push_back(task);
        self.park.unpark();
    }

    pub fn pop(&self) -> Option<Arc<LocalTask>> {
        self.tasks.lock().pop_front()
    }

    pub fn len(&self) -> usize {
        self.tasks.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An executor that runs its tasks on the thread that calls
/// [`LocalExecutor::run_until_idle`] or [`LocalExecutor::block_on`]; tasks
/// may be woken from any thread. Dropping the last clone drops every
/// unfinished task (their handles report [`TaskError::Cancelled`](super::TaskError)). When it has nothing to run, `block_on`
/// waits with its [`Park`] ([`SpinPark`] by default, for environments
/// without threads; the platform runtime provides one that sleeps).
#[derive(Clone)]
pub struct LocalExecutor {
    queue: Arc<LocalQueue>,
}

impl LocalExecutor {
    /// An executor that spins when idle.
    pub fn new() -> LocalExecutor {
        LocalExecutor::with_park(Arc::new(SpinPark::new()))
    }

    /// An executor that waits with `park` when idle.
    pub fn with_park(park: Arc<dyn Park + Send + Sync>) -> LocalExecutor {
        LocalExecutor {
            queue: Arc::new(LocalQueue { tasks: SpinLock::new(VecDeque::new()), registry: TaskRegistry::new(), park }),
        }
    }

    pub fn park(&self) -> &Arc<dyn Park + Send + Sync> {
        &self.queue.park
    }

    /// The tasks waiting to run.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Runs the tasks in the run queue (and those they wake meanwhile)
    /// until it is empty; returns the polls made.
    pub fn run_until_idle(&self) -> usize {
        let mut polls = 0;
        while let Some(task) = self.queue.pop() {
            task.queued.store(false, Ordering::Release);
            let waker = Waker::from(task.clone());
            let mut context = Context::from_waker(&waker);
            let mut slot = task.future.lock();
            if let Some(future) = slot.as_mut()
                && future.as_mut().poll(&mut context).is_ready()
            {
                *slot = None;
                self.queue.registry.remove(task.key.load(Ordering::Acquire), &task);
            }
            polls += 1;
        }
        polls
    }

    /// Runs `future` to completion on this thread, running the tasks of the
    /// executor meanwhile, and waiting with the executor's [`Park`] when
    /// nothing is ready.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        let mut future = pin!(future);
        let woken = Arc::new(BlockOnWaker { woken: AtomicBool::new(true), park: self.queue.park.clone() });
        let waker = Waker::from(woken.clone());
        let mut context = Context::from_waker(&waker);
        loop {
            if woken.woken.swap(false, Ordering::AcqRel)
                && let Poll::Ready(output) = future.as_mut().poll(&mut context)
            {
                return output;
            }
            if self.run_until_idle() == 0 && !woken.woken.load(Ordering::Acquire) {
                self.queue.park.park(None);
            }
        }
    }
}

impl Default for LocalExecutor {
    fn default() -> LocalExecutor {
        LocalExecutor::new()
    }
}

impl Executor for LocalExecutor {
    fn spawn_boxed(&self, future: BoxFuture) {
        let task = Arc::new(LocalTask {
            future: SpinLock::new(Some(future)),
            queued: AtomicBool::new(false),
            queue: Arc::downgrade(&self.queue),
            key: core::sync::atomic::AtomicUsize::new(0),
        });
        task.key.store(self.queue.registry.insert(&task), Ordering::Release);
        task.schedule();
    }
}

/// The waker of the future of [`LocalExecutor::block_on`].
pub struct BlockOnWaker {
    woken: AtomicBool,
    park: Arc<dyn Park + Send + Sync>,
}

impl Wake for BlockOnWaker {
    fn wake(self: Arc<BlockOnWaker>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<BlockOnWaker>) {
        self.woken.store(true, Ordering::Release);
        self.park.unpark();
    }
}
