use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use umilib::runtime::{
    Channel, Clock, Elapsed, Executor, Instant, LocalExecutor, SpinPark, Timer, TimerPark, TimerQueue,
};

/// A clock the test moves by hand.
#[derive(Default)]
struct ManualClock(AtomicU64);

impl ManualClock {
    fn advance(&self, duration: Duration) {
        self.0.fetch_add(duration.as_nanos() as u64, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        Instant::from_nanos(self.0.load(Ordering::SeqCst))
    }
}

#[test]
fn timer_queues_fire_in_deadline_order() {
    let mut queue = TimerQueue::new();
    let late = queue.insert(Instant::from_nanos(30), None);
    let early = queue.insert(Instant::from_nanos(10), None);
    let removed = queue.insert(Instant::from_nanos(5), None);
    assert!(queue.remove(removed));
    assert!(!queue.remove(removed));
    assert_eq!(queue.next_deadline(), Some(Instant::from_nanos(10)));
    assert_eq!(queue.fire(Instant::from_nanos(9)), 0);
    assert_eq!(queue.fire(Instant::from_nanos(10)), 1);
    assert!(!queue.contains(early) && queue.contains(late));
    assert_eq!(queue.next_deadline(), Some(Instant::from_nanos(30)));
    assert_eq!(queue.fire(Instant::MAX), 1);
    assert_eq!(queue.next_deadline(), None);
    assert!(queue.is_empty());
    // Instants saturate.
    assert_eq!(Instant::MAX + Duration::from_secs(1), Instant::MAX);
    assert_eq!(Instant::ZERO - Instant::from_nanos(5), Duration::ZERO);
}

#[test]
fn sleeps_and_timeouts_follow_the_clock() {
    let clock = Arc::new(ManualClock::default());
    let timer = Timer::new(clock.clone());
    let executor = LocalExecutor::new();
    let sleeper = executor.spawn({
        let timer = timer.clone();
        async move { timer.sleep(Duration::from_millis(50)).await }
    });
    executor.run_until_idle();
    assert_eq!(timer.queue().lock().len(), 1);
    clock.advance(Duration::from_millis(49));
    assert_eq!(timer.fire(), Some(Instant::from_nanos(50_000_000)));
    executor.run_until_idle();
    assert!(!sleeper.is_finished());
    clock.advance(Duration::from_millis(1));
    assert_eq!(timer.fire(), None);
    executor.run_until_idle();
    assert!(sleeper.is_finished());
    // A timeout that runs out gives Elapsed; one whose future finishes first gives the output.
    let (_sender, receiver) = Channel::oneshot::<u8>();
    let timed = executor.spawn({
        let timer = timer.clone();
        async move { timer.timeout(Duration::from_millis(10), receiver).await }
    });
    executor.run_until_idle();
    clock.advance(Duration::from_millis(10));
    timer.fire();
    assert_eq!(executor.block_on(timed), Ok(Err(Elapsed)));
    let (sender, receiver) = Channel::oneshot::<u8>();
    sender.send(3).unwrap();
    let quick = timer.timeout(Duration::from_millis(10), receiver);
    assert_eq!(executor.block_on(quick), Ok(Ok(3)));
    // A dropped sleep removes its timer.
    let sleep = timer.sleep(Duration::from_secs(5));
    let handle = executor.spawn(sleep);
    executor.run_until_idle();
    assert_eq!(timer.queue().lock().len(), 1);
    handle.abort();
    executor.run_until_idle();
    assert_eq!(timer.queue().lock().len(), 0);
}

#[test]
fn timer_parks_drive_the_timers_of_block_on() {
    /// A clock of the real time, for this test.
    struct SystemClock(std::time::Instant);
    impl Clock for SystemClock {
        fn now(&self) -> Instant {
            Instant::from_nanos(self.0.elapsed().as_nanos() as u64)
        }
    }
    let timer = Timer::new(Arc::new(SystemClock(std::time::Instant::now())));
    let park = Arc::new(TimerPark::new(timer.clone(), Arc::new(SpinPark::new())));
    let executor = LocalExecutor::with_park(park);
    let start = std::time::Instant::now();
    executor.block_on(timer.sleep(Duration::from_millis(30)));
    assert!(start.elapsed() >= Duration::from_millis(30));
}
