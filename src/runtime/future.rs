use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// The output of a [`Select`]: which future finished first, with its output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Either<A, B> {
    First(A),
    Second(B),
}

/// Runs two futures together until both finish.
pub struct Join<A: Future, B: Future> {
    first: Pin<Box<A>>,
    second: Pin<Box<B>>,
    outputs: (Option<A::Output>, Option<B::Output>),
}

impl<A: Future, B: Future> Join<A, B> {
    pub fn new(first: A, second: B) -> Join<A, B> {
        Join { first: Box::pin(first), second: Box::pin(second), outputs: (None, None) }
    }
}

// The futures are boxed and the outputs never pinned, so a `Join` may move.
impl<A: Future, B: Future> Unpin for Join<A, B> {}

impl<A: Future, B: Future> Future for Join<A, B> {
    type Output = (A::Output, B::Output);

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<(A::Output, B::Output)> {
        let this = &mut *self;
        if this.outputs.0.is_none()
            && let Poll::Ready(output) = this.first.as_mut().poll(context)
        {
            this.outputs.0 = Some(output);
        }
        if this.outputs.1.is_none()
            && let Poll::Ready(output) = this.second.as_mut().poll(context)
        {
            this.outputs.1 = Some(output);
        }
        if this.outputs.0.is_some() && this.outputs.1.is_some() {
            let (first, second) = (this.outputs.0.take(), this.outputs.1.take());
            return Poll::Ready((first.expect("finished"), second.expect("finished")));
        }
        Poll::Pending
    }
}

/// Runs two futures together until one finishes (the first one polled
/// first); the other is dropped with the `Select`.
pub struct Select<A: Future, B: Future> {
    first: Pin<Box<A>>,
    second: Pin<Box<B>>,
}

impl<A: Future, B: Future> Select<A, B> {
    pub fn new(first: A, second: B) -> Select<A, B> {
        Select { first: Box::pin(first), second: Box::pin(second) }
    }
}

impl<A: Future, B: Future> Future for Select<A, B> {
    type Output = Either<A::Output, B::Output>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Either<A::Output, B::Output>> {
        if let Poll::Ready(output) = self.first.as_mut().poll(context) {
            return Poll::Ready(Either::First(output));
        }
        if let Poll::Ready(output) = self.second.as_mut().poll(context) {
            return Poll::Ready(Either::Second(output));
        }
        Poll::Pending
    }
}

/// Runs futures together until all finish; their outputs in order.
pub struct JoinAll<F: Future> {
    futures: Vec<Option<Pin<Box<F>>>>,
    outputs: Vec<Option<F::Output>>,
}

impl<F: Future> JoinAll<F> {
    pub fn new(futures: impl IntoIterator<Item = F>) -> JoinAll<F> {
        let futures: Vec<Option<Pin<Box<F>>>> = futures.into_iter().map(|future| Some(Box::pin(future))).collect();
        let outputs = futures.iter().map(|_| None).collect();
        JoinAll { futures, outputs }
    }
}

// The futures are boxed and the outputs never pinned, so a `JoinAll` may move.
impl<F: Future> Unpin for JoinAll<F> {}

impl<F: Future> Future for JoinAll<F> {
    type Output = Vec<F::Output>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Vec<F::Output>> {
        let this = &mut *self;
        let mut pending = false;
        for (slot, output) in this.futures.iter_mut().zip(this.outputs.iter_mut()) {
            if let Some(future) = slot {
                match future.as_mut().poll(context) {
                    Poll::Ready(value) => {
                        *output = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            return Poll::Pending;
        }
        Poll::Ready(this.outputs.iter_mut().map(|output| output.take().expect("finished")).collect())
    }
}

/// A future that is pending once (waking itself), so that other tasks run.
#[derive(Debug, Default)]
pub struct YieldNow {
    yielded: bool,
}

impl YieldNow {
    pub const fn new() -> YieldNow {
        YieldNow { yielded: false }
    }
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            return Poll::Ready(());
        }
        self.yielded = true;
        context.waker().wake_by_ref();
        Poll::Pending
    }
}
