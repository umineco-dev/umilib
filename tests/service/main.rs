//! Tests of `umilib::service`: the behaviour its documentation promises.

mod pattern;
mod router;
mod service;

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Runs `future` to completion, polling it again whenever it is not ready
/// (the futures of these tests yield at most a few times).
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}

/// A future that is pending once (it wakes its task) and then ready.
#[derive(Default)]
pub struct YieldOnce(bool);

impl YieldOnce {
    pub fn new() -> YieldOnce {
        YieldOnce(false)
    }
}

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: std::pin::Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        context.waker().wake_by_ref();
        Poll::Pending
    }
}
