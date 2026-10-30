use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

use super::sync::{AtomicWaker, SpinLock};

/// Why a task gave no result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskError {
    /// The task was aborted through its [`JoinHandle`], or dropped by its executor before it finished.
    Cancelled,
}

/// What a running task and its [`JoinHandle`] share: the result, the waker
/// of the joiner, the waker of the task and whether it is aborted.
#[derive(Debug)]
pub struct TaskState<T> {
    result: SpinLock<Option<Result<T, TaskError>>>,
    done: AtomicBool,
    aborted: AtomicBool,
    joiner: AtomicWaker,
    /// The waker of the task, kept while the handle exists (to wake it when aborted).
    task: AtomicWaker,
    handle: AtomicBool,
}

impl<T> TaskState<T> {
    pub fn new() -> TaskState<T> {
        TaskState {
            result: SpinLock::new(None),
            done: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
            joiner: AtomicWaker::new(),
            task: AtomicWaker::new(),
            handle: AtomicBool::new(true),
        }
    }

    /// Records the result (the first one only) and wakes the joiner.
    pub fn complete(&self, result: Result<T, TaskError>) {
        {
            let mut slot = self.result.lock();
            if self.done.load(Ordering::Acquire) {
                return;
            }
            *slot = Some(result);
            self.done.store(true, Ordering::Release);
        }
        self.joiner.wake();
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }
}

impl<T> Default for TaskState<T> {
    fn default() -> TaskState<T> {
        TaskState::new()
    }
}

/// The future an executor runs for a spawned future: it polls the future,
/// gives its output to the [`JoinHandle`], and stops early when aborted.
/// Dropped unfinished, it reports [`TaskError::Cancelled`].
pub struct TaskFuture<F: Future> {
    future: Option<Pin<alloc::boxed::Box<F>>>,
    state: Arc<TaskState<F::Output>>,
}

impl<F: Future> TaskFuture<F> {
    /// The task of `future` and the handle of its result.
    pub fn new(future: F) -> (TaskFuture<F>, JoinHandle<F::Output>) {
        let state = Arc::new(TaskState::new());
        (TaskFuture { future: Some(alloc::boxed::Box::pin(future)), state: state.clone() }, JoinHandle { state })
    }
}

impl<F: Future> Future for TaskFuture<F> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        if this.state.aborted.load(Ordering::Acquire) {
            this.future = None;
            this.state.complete(Err(TaskError::Cancelled));
            return Poll::Ready(());
        }
        let Some(future) = this.future.as_mut() else { return Poll::Ready(()) };
        if this.state.handle.load(Ordering::Acquire) {
            this.state.task.register(context.waker());
            // A handle dropped meanwhile cleared the slot before this registration: clear it again.
            if !this.state.handle.load(Ordering::Acquire) {
                this.state.task.clear();
            }
        }
        match future.as_mut().poll(context) {
            Poll::Ready(output) => {
                this.future = None;
                this.state.task.clear();
                this.state.complete(Ok(output));
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F: Future> Drop for TaskFuture<F> {
    fn drop(&mut self) {
        if self.future.take().is_some() {
            self.state.complete(Err(TaskError::Cancelled));
        }
    }
}

/// The result of a spawned task, as a future; dropping it detaches the task.
///
/// While a handle exists, the task's waker is kept in it to wake the task
/// when it is aborted.
#[derive(Debug)]
pub struct JoinHandle<T> {
    state: Arc<TaskState<T>>,
}

impl<T> JoinHandle<T> {
    /// Whether the task has finished (or was cancelled).
    pub fn is_finished(&self) -> bool {
        self.state.is_done()
    }

    /// Stops the task at its next poll: its future is dropped and the
    /// handle gives [`TaskError::Cancelled`] (unless it already finished).
    pub fn abort(&self) {
        self.state.aborted.store(true, Ordering::Release);
        self.state.task.wake();
    }

    /// The result if the task has finished, taking it.
    pub fn try_take(&mut self) -> Option<Result<T, TaskError>> {
        if !self.state.is_done() {
            return None;
        }
        self.state.result.lock().take()
    }
}

impl<T> Drop for JoinHandle<T> {
    fn drop(&mut self) {
        // Nothing can abort the task any more: its waker kept for that would only keep it alive.
        self.state.handle.store(false, Ordering::Release);
        self.state.task.clear();
    }
}

impl<T> Future for JoinHandle<T> {
    type Output = Result<T, TaskError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<T, TaskError>> {
        self.state.joiner.register(context.waker());
        if self.state.is_done() {
            // A handle polled again after its result was taken sees a cancelled task.
            return Poll::Ready(self.state.result.lock().take().unwrap_or(Err(TaskError::Cancelled)));
        }
        Poll::Pending
    }
}
