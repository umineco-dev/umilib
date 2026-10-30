use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;

/// A mutual exclusion lock that spins while another holder has it, for the
/// short critical sections of the runtime (queues, wakers) where no
/// operating system lock is available.
pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the lock gives one holder at a time access to the value, which may
// be sent to the holder's thread.
unsafe impl<T: Send> Send for SpinLock<T> {}
// SAFETY: as above; shared access only ever reaches the value through the lock.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> SpinLock<T> {
        SpinLock { locked: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }

    /// Takes the lock, spinning until it is free.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        loop {
            if let Some(guard) = self.try_lock() {
                return guard;
            }
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
    }

    /// Takes the lock if it is free.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinLockGuard { lock: self })
    }

    /// The value, through exclusive access to the lock.
    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }

    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }
}

impl<T: Default> Default for SpinLock<T> {
    fn default() -> SpinLock<T> {
        SpinLock::new(T::default())
    }
}

impl<T: fmt::Debug> fmt::Debug for SpinLock<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_lock() {
            Some(guard) => formatter.debug_struct("SpinLock").field("value", &*guard).finish(),
            None => formatter.write_str("SpinLock { <locked> }"),
        }
    }
}

/// The access a [`SpinLock`] gives; the lock is released when it is dropped.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock, so no other reference to the value exists.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the lock, so no other reference to the value exists.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

/// A slot for the waker of the one task waiting on something, which another
/// thread wakes.
#[derive(Debug, Default)]
pub struct AtomicWaker {
    waker: SpinLock<Option<Waker>>,
}

impl AtomicWaker {
    pub const fn new() -> AtomicWaker {
        AtomicWaker { waker: SpinLock::new(None) }
    }

    /// Keeps `waker` (replacing the one kept unless it wakes the same task).
    pub fn register(&self, waker: &Waker) {
        let mut slot = self.waker.lock();
        match &mut *slot {
            Some(current) if current.will_wake(waker) => {}
            _ => *slot = Some(waker.clone()),
        }
    }

    /// Wakes the waker kept, if any, and forgets it.
    pub fn wake(&self) {
        let waker = self.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Forgets the waker kept.
    pub fn clear(&self) {
        self.waker.lock().take();
    }
}
