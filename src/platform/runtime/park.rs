use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::Thread;
use std::time::Duration;

use crate::runtime::Park;

/// A [`Park`] of one thread: `std::thread::park`, with a flag so that an
/// unpark before the park is not lost.
#[derive(Debug)]
pub struct ThreadPark {
    thread: Thread,
    notified: AtomicBool,
}

impl ThreadPark {
    /// A parker of the calling thread.
    pub fn current() -> ThreadPark {
        ThreadPark { thread: std::thread::current(), notified: AtomicBool::new(false) }
    }

    pub fn thread(&self) -> &Thread {
        &self.thread
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
