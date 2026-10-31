use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::ops::{Add, Sub};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use super::sync::SpinLock;

/// A point of a monotonic clock: nanoseconds since the clock's own origin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    /// The origin of the clock.
    pub const ZERO: Instant = Instant(0);
    /// The latest instant.
    pub const MAX: Instant = Instant(u64::MAX);

    pub const fn from_nanos(nanoseconds: u64) -> Instant {
        Instant(nanoseconds)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// The time from `earlier` to this instant; zero if `earlier` is later.
    pub fn saturating_duration_since(self, earlier: Instant) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }

    /// This instant plus `duration`, the latest instant if it overflows.
    pub fn saturating_add(self, duration: Duration) -> Instant {
        Instant(self.0.saturating_add(u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)))
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, duration: Duration) -> Instant {
        self.saturating_add(duration)
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, earlier: Instant) -> Duration {
        self.saturating_duration_since(earlier)
    }
}

/// A monotonic clock (provided by the platform, or by a test).
pub trait Clock {
    fn now(&self) -> Instant;
}

/// The key of a timer in a [`TimerQueue`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimerKey(u64);

impl TimerKey {
    /// The key of the number `value` (as [`TimerKey::value`] gives it).
    pub const fn from_value(value: u64) -> TimerKey {
        TimerKey(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Timers by deadline, each with the waker of the task waiting on it. A
/// driver (the platform reactor, or a [`Park`](super::Park) adapter) asks
/// for [`TimerQueue::next_deadline`] to know how long to wait and calls
/// [`TimerQueue::fire`] to wake the timers that expired.
#[derive(Debug, Default)]
pub struct TimerQueue {
    /// The timers waiting, in order of deadline; exactly those of `timers`,
    /// so that removing a timer frees it at once.
    deadlines: BTreeSet<(Instant, TimerKey)>,
    timers: BTreeMap<TimerKey, (Instant, Option<Waker>)>,
    next_key: u64,
}

impl TimerQueue {
    pub fn new() -> TimerQueue {
        TimerQueue::default()
    }

    /// Adds a timer of `deadline` whose expiry wakes `waker`.
    pub fn insert(&mut self, deadline: Instant, waker: Option<Waker>) -> TimerKey {
        let key = TimerKey(self.next_key);
        self.next_key += 1;
        self.deadlines.insert((deadline, key));
        self.timers.insert(key, (deadline, waker));
        key
    }

    /// Replaces the waker of the timer `key`; false if it is not there (expired or removed).
    pub fn update(&mut self, key: TimerKey, waker: &Waker) -> bool {
        self.swap_waker(key, waker).is_some()
    }

    /// Replaces the waker of the timer `key` and returns the one it had, or
    /// `None` if the timer is not there. Dropping a waker can drop its task,
    /// and with it a future that uses this queue, so a caller that holds the
    /// queue under a lock drops what this returns after releasing it.
    pub fn swap_waker(&mut self, key: TimerKey, waker: &Waker) -> Option<Option<Waker>> {
        let (_, slot) = self.timers.get_mut(&key)?;
        if slot.as_ref().is_some_and(|current| current.will_wake(waker)) {
            return Some(None);
        }
        Some(slot.replace(waker.clone()))
    }

    /// Removes the timer `key`; whether it was there.
    pub fn remove(&mut self, key: TimerKey) -> bool {
        self.take(key).is_some()
    }

    /// Removes the timer `key` and returns its waker, or `None` if it is not
    /// there; as for [`TimerQueue::swap_waker`], a caller that holds the queue
    /// under a lock drops the waker after releasing it.
    pub fn take(&mut self, key: TimerKey) -> Option<Option<Waker>> {
        let (deadline, waker) = self.timers.remove(&key)?;
        self.deadlines.remove(&(deadline, key));
        Some(waker)
    }

    /// Whether the timer `key` is waiting (neither expired nor removed).
    pub fn contains(&self, key: TimerKey) -> bool {
        self.timers.contains_key(&key)
    }

    /// The timers waiting.
    pub fn len(&self) -> usize {
        self.timers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.timers.is_empty()
    }

    /// The earliest deadline of the timers waiting.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.first().map(|(deadline, _)| *deadline)
    }

    /// Removes the timers whose deadline is `now` or earlier and wakes
    /// them; returns how many expired.
    pub fn fire(&mut self, now: Instant) -> usize {
        let mut wakers = Vec::new();
        let expired = self.expire(now, &mut wakers);
        wakers.into_iter().for_each(Waker::wake);
        expired
    }

    /// Removes the timers whose deadline is `now` or earlier and appends
    /// their wakers to `wakers` without waking them (for a queue behind a
    /// lock: a woken task may run, or be dropped, at once, and use the
    /// queue); returns how many expired.
    pub fn expire(&mut self, now: Instant, wakers: &mut Vec<Waker>) -> usize {
        let mut expired = 0;
        while let Some(&(deadline, key)) = self.deadlines.first() {
            if deadline > now {
                break;
            }
            self.deadlines.pop_first();
            if let Some((_, waker)) = self.timers.remove(&key) {
                expired += 1;
                wakers.extend(waker);
            }
        }
        expired
    }
}

/// A [`TimerQueue`] with its clock, shared by the futures that wait on it
/// ([`Timer::sleep`], [`Timer::timeout`]) and the driver that fires it. A
/// driver that waits in its own loop (a reactor thread) is told of every
/// new timer through the [`Park`](super::Park) given to [`Timer::with_driver`],
/// so that it can wait less.
#[derive(Clone)]
pub struct Timer {
    queue: Arc<SpinLock<TimerQueue>>,
    clock: Arc<dyn Clock + Send + Sync>,
    driver: Option<Arc<dyn super::Park + Send + Sync>>,
}

impl Timer {
    pub fn new(clock: Arc<dyn Clock + Send + Sync>) -> Timer {
        Timer { queue: Arc::new(SpinLock::new(TimerQueue::new())), clock, driver: None }
    }

    /// A timer whose new timers unpark `driver`.
    pub fn with_driver(clock: Arc<dyn Clock + Send + Sync>, driver: Arc<dyn super::Park + Send + Sync>) -> Timer {
        Timer { queue: Arc::new(SpinLock::new(TimerQueue::new())), clock, driver: Some(driver) }
    }

    /// Adds a timer of `deadline` (telling the driver).
    pub fn insert(&self, deadline: Instant, waker: Option<Waker>) -> TimerKey {
        let key = self.queue.lock().insert(deadline, waker);
        if let Some(driver) = &self.driver {
            driver.unpark();
        }
        key
    }

    pub fn now(&self) -> Instant {
        self.clock.now()
    }

    pub fn clock(&self) -> &Arc<dyn Clock + Send + Sync> {
        &self.clock
    }

    pub fn queue(&self) -> &Arc<SpinLock<TimerQueue>> {
        &self.queue
    }

    /// A future that completes `duration` from now.
    pub fn sleep(&self, duration: Duration) -> Sleep {
        self.sleep_until(self.now() + duration)
    }

    /// A future that completes at `deadline`.
    pub fn sleep_until(&self, deadline: Instant) -> Sleep {
        Sleep { timer: self.clone(), deadline, key: None }
    }

    /// `future`, or [`Elapsed`] if it has not finished `duration` from now.
    pub fn timeout<F: Future>(&self, duration: Duration, future: F) -> Timeout<F> {
        Timeout { future: alloc::boxed::Box::pin(future), sleep: self.sleep(duration) }
    }

    /// Wakes the timers that expired (after releasing the queue, which
    /// their tasks may use); the deadline of the next one.
    pub fn fire(&self) -> Option<Instant> {
        let now = self.now();
        let mut wakers = Vec::new();
        let next = {
            let mut queue = self.queue.lock();
            queue.expire(now, &mut wakers);
            queue.next_deadline()
        };
        wakers.into_iter().for_each(Waker::wake);
        next
    }

    /// The same timer (its queue and clock) with `driver` told of every new timer.
    pub fn driven_by(&self, driver: Arc<dyn super::Park + Send + Sync>) -> Timer {
        Timer { queue: self.queue.clone(), clock: self.clock.clone(), driver: Some(driver) }
    }
}

/// The future of [`Timer::sleep`]; dropping it removes its timer.
pub struct Sleep {
    timer: Timer,
    deadline: Instant,
    key: Option<TimerKey>,
}

impl Sleep {
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        if self.timer.now() >= self.deadline {
            if let Some(key) = self.key.take() {
                // The waker is dropped once the queue is released.
                let _waker = self.timer.queue.lock().take(key);
            }
            return Poll::Ready(());
        }
        let deadline = self.deadline;
        if let Some(key) = self.key {
            let replaced = self.timer.queue.lock().swap_waker(key, context.waker());
            if replaced.is_some() {
                return Poll::Pending;
            }
        }
        let key = self.timer.insert(deadline, Some(context.waker().clone()));
        self.key = Some(key);
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            // The waker is dropped once the queue is released.
            let _waker = self.timer.queue.lock().take(key);
        }
    }
}

/// The error of a [`Timeout`] whose time ran out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed;

/// The future of [`Timer::timeout`].
pub struct Timeout<F: Future> {
    future: Pin<alloc::boxed::Box<F>>,
    sleep: Sleep,
}

impl<F: Future> Future for Timeout<F> {
    type Output = Result<F::Output, Elapsed>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<F::Output, Elapsed>> {
        if let Poll::Ready(output) = self.future.as_mut().poll(context) {
            return Poll::Ready(Ok(output));
        }
        match Pin::new(&mut self.sleep).poll(context) {
            Poll::Ready(()) => Poll::Ready(Err(Elapsed)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A [`Park`](super::Park) that drives a [`Timer`]: before waiting it wakes
/// the timers that expired and waits at most until the next deadline.
pub struct TimerPark {
    timer: Timer,
    park: Arc<dyn super::Park + Send + Sync>,
}

impl TimerPark {
    pub fn new(timer: Timer, park: Arc<dyn super::Park + Send + Sync>) -> TimerPark {
        TimerPark { timer, park }
    }

    pub fn timer(&self) -> &Timer {
        &self.timer
    }
}

impl super::Park for TimerPark {
    fn park(&self, timeout: Option<Duration>) {
        let wait = match self.timer.fire() {
            Some(deadline) => {
                let until = deadline - self.timer.now();
                Some(timeout.map_or(until, |timeout| timeout.min(until)))
            }
            None => timeout,
        };
        if wait != Some(Duration::ZERO) {
            self.park.park(wait);
        }
        self.timer.fire();
    }

    fn unpark(&self) {
        self.park.unpark();
    }
}
