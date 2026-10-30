//! Tests of `umilib::runtime`: the behaviour its documentation promises.

mod channel;
mod executor;
mod io;
mod time;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use umilib::runtime::Park;

/// A [`Park`] of the test threads: `std::thread::park`.
pub struct ThreadPark {
    thread: std::thread::Thread,
    notified: AtomicBool,
}

impl ThreadPark {
    /// A parker of the calling thread.
    pub fn current() -> Arc<ThreadPark> {
        Arc::new(ThreadPark { thread: std::thread::current(), notified: AtomicBool::new(false) })
    }
}

impl Park for ThreadPark {
    fn park(&self, timeout: Option<Duration>) {
        if self.notified.swap(false, Ordering::AcqRel) {
            return;
        }
        match timeout {
            Some(timeout) => std::thread::park_timeout(timeout),
            None => std::thread::park(),
        }
        self.notified.store(false, Ordering::Release);
    }

    fn unpark(&self) {
        self.notified.store(true, Ordering::Release);
        self.thread.unpark();
    }
}
