use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

/// How an idle executor waits until it is woken: [`Park::park`] returns
/// after [`Park::unpark`] (called from any thread, possibly before
/// `park`), after the timeout, or spuriously.
pub trait Park {
    /// Waits for an unpark, at most `timeout` if given.
    fn park(&self, timeout: Option<Duration>);

    /// Ends the current or next wait.
    fn unpark(&self);
}

/// A [`Park`] that spins, for environments without threads or clocks:
/// without a timeout it spins until unparked; with one, it returns at once
/// (it cannot measure time), leaving the waiting to the caller's loop.
#[derive(Debug, Default)]
pub struct SpinPark {
    notified: AtomicBool,
}

impl SpinPark {
    pub const fn new() -> SpinPark {
        SpinPark { notified: AtomicBool::new(false) }
    }
}

impl Park for SpinPark {
    fn park(&self, timeout: Option<Duration>) {
        if timeout.is_some() {
            self.notified.store(false, Ordering::Release);
            return;
        }
        while !self.notified.swap(false, Ordering::AcqRel) {
            core::hint::spin_loop();
        }
    }

    fn unpark(&self) {
        self.notified.store(true, Ordering::Release);
    }
}
