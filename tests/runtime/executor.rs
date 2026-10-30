use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use umilib::runtime::{Channel, Either, Executor, Join, JoinAll, LocalExecutor, Select, SpinLock, TaskError, YieldNow};

use crate::ThreadPark;

#[test]
fn local_executors_run_every_task_to_completion() {
    let executor = LocalExecutor::new();
    let counter = Arc::new(AtomicUsize::new(0));
    let handles: Vec<_> = (0..1000)
        .map(|index| {
            let counter = counter.clone();
            executor.spawn(async move {
                YieldNow::new().await;
                counter.fetch_add(1, Ordering::Relaxed);
                index * 2
            })
        })
        .collect();
    assert_eq!(executor.queued(), 1000);
    let polls = executor.run_until_idle();
    // Each task is polled twice: before and after its yield.
    assert_eq!(polls, 2000);
    assert_eq!(counter.load(Ordering::Relaxed), 1000);
    let results = executor.block_on(JoinAll::new(handles));
    assert_eq!(results, (0..1000).map(|index| Ok(index * 2)).collect::<Vec<_>>());
}

#[test]
fn tasks_are_woken_from_other_threads() {
    let executor = LocalExecutor::with_park(ThreadPark::current());
    let (sender, mut receiver) = Channel::bounded::<u32>(4);
    let consumer = executor.spawn(async move {
        let mut sum = 0;
        while let Some(value) = receiver.receive().await {
            sum += value;
        }
        sum
    });
    let producers: Vec<_> = (0..4)
        .map(|thread| {
            let sender = sender.clone();
            std::thread::spawn(move || {
                for value in 0..250 {
                    // A sender on a thread without an executor retries when full.
                    let mut value = thread * 1000 + value;
                    loop {
                        match sender.try_send(value) {
                            Ok(()) => break,
                            Err(error) => {
                                value = error.value;
                                std::thread::yield_now();
                            }
                        }
                    }
                }
            })
        })
        .collect();
    drop(sender);
    let total = executor.block_on(async {
        let result = consumer.await;
        result.unwrap()
    });
    producers.into_iter().for_each(|thread| thread.join().unwrap());
    let expected: u32 = (0..4).map(|thread| (0..250).map(|value| thread * 1000 + value).sum::<u32>()).sum();
    assert_eq!(total, expected);
}

#[test]
fn aborted_tasks_stop_and_report_cancellation() {
    let executor = LocalExecutor::new();
    let dropped = Arc::new(AtomicUsize::new(0));
    struct Guard(Arc<AtomicUsize>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let guard = Guard(dropped.clone());
    let (_sender, receiver) = Channel::oneshot::<u32>();
    let handle = executor.spawn(async move {
        let _guard = guard;
        receiver.await
    });
    executor.run_until_idle();
    assert!(!handle.is_finished());
    handle.abort();
    executor.run_until_idle();
    assert_eq!(dropped.load(Ordering::Relaxed), 1, "the future is dropped");
    assert_eq!(executor.block_on(handle), Err(TaskError::Cancelled));
    // A task that finished before the abort keeps its result.
    let mut handle = executor.spawn(async { 7 });
    executor.run_until_idle();
    handle.abort();
    assert_eq!(handle.try_take(), Some(Ok(7)));
    // The tasks queued in an executor dropped are cancelled.
    let gone = LocalExecutor::new();
    let handle = gone.spawn(async { 1 });
    drop(gone);
    assert_eq!(executor.block_on(handle), Err(TaskError::Cancelled));
    // A pending task whose executor is gone is dropped with its last waker.
    let gone = LocalExecutor::new();
    let (sender, receiver) = Channel::oneshot::<u32>();
    let handle = gone.spawn(receiver);
    gone.run_until_idle();
    drop(gone);
    drop(sender);
    assert_eq!(executor.block_on(handle), Err(TaskError::Cancelled));
}

#[test]
fn combinators_join_and_select() {
    let executor = LocalExecutor::new();
    let (first_sender, first) = Channel::oneshot::<&str>();
    let (second_sender, second) = Channel::oneshot::<u32>();
    let joined = executor.spawn(Join::new(first, second));
    executor.run_until_idle();
    first_sender.send("a").unwrap();
    executor.run_until_idle();
    assert!(!joined.is_finished(), "a join waits for both");
    second_sender.send(2).unwrap();
    assert_eq!(executor.block_on(joined), Ok((Ok("a"), Ok(2))));
    let (sender, receiver) = Channel::oneshot::<u32>();
    let (_never, pending) = Channel::oneshot::<u32>();
    let selected = executor.spawn(Select::new(pending, receiver));
    sender.send(5).unwrap();
    assert_eq!(executor.block_on(selected), Ok(Either::Second(Ok(5))));
}

#[test]
fn spin_locks_exclude_each_other() {
    let lock = Arc::new(SpinLock::new(0u64));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let lock = lock.clone();
            std::thread::spawn(move || {
                for _ in 0..10_000 {
                    *lock.lock() += 1;
                }
            })
        })
        .collect();
    threads.into_iter().for_each(|thread| thread.join().unwrap());
    assert_eq!(*lock.lock(), 80_000);
    let guard = lock.lock();
    assert!(lock.try_lock().is_none());
    drop(guard);
    assert!(lock.try_lock().is_some());
}

#[test]
fn block_on_waits_for_wakes_from_other_threads() {
    let executor = LocalExecutor::with_park(ThreadPark::current());
    let (sender, receiver) = Channel::oneshot::<u64>();
    let thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        sender.send(99).unwrap();
    });
    assert_eq!(executor.block_on(receiver), Ok(99));
    thread.join().unwrap();
}

#[test]
fn registries_forget_tasks_by_identity() {
    use umilib::runtime::TaskRegistry;
    let registry = TaskRegistry::new();
    let (first, second) = (Arc::new(1u8), Arc::new(2u8));
    let key = registry.insert(&first);
    assert_eq!(registry.len(), 1);
    // A task drained and then dropped after its key was reused leaves the new task alone.
    assert_eq!(registry.drain().len(), 1);
    let reused = registry.insert(&second);
    assert_eq!(reused, key);
    registry.remove(key, &first);
    assert_eq!(registry.len(), 1);
    registry.remove(key, &second);
    assert!(registry.is_empty());
    // The freed slot is reused.
    assert_eq!(registry.insert(&first), key);
}

#[test]
fn timers_wake_wakers_that_drop_sleeps_of_the_same_timer() {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Wake, Waker};

    use umilib::runtime::{Clock, Instant, Sleep, Timer};

    // A clock that the test moves.
    struct Manual(SpinLock<u64>);
    impl Clock for Manual {
        fn now(&self) -> Instant {
            Instant::from_nanos(*self.0.lock())
        }
    }
    // A waker that drops a sleep when woken, as an executor that drops a task's future at once does.
    struct Dropping(Mutex<Option<Sleep>>);
    impl Wake for Dropping {
        fn wake(self: Arc<Dropping>) {
            self.0.lock().unwrap().take();
        }
    }
    let clock = Arc::new(Manual(SpinLock::new(0)));
    let timer = Timer::new(clock.clone());
    let mut longer = timer.sleep(Duration::from_secs(60));
    let mut shorter = timer.sleep(Duration::from_millis(1));
    let noop = Waker::from(Arc::new(Dropping(Mutex::new(None))));
    assert!(Pin::new(&mut longer).poll(&mut Context::from_waker(&noop)).is_pending());
    let dropping = Arc::new(Dropping(Mutex::new(Some(longer))));
    let waker = Waker::from(dropping.clone());
    assert!(Pin::new(&mut shorter).poll(&mut Context::from_waker(&waker)).is_pending());
    assert_eq!(timer.queue().lock().len(), 2);
    *clock.0.lock() = 2_000_000;
    // The wake drops `longer`, whose drop removes its timer from the queue being fired (the
    // deadline returned is read before the wakes, so it may still be that of `longer`).
    timer.fire();
    assert!(dropping.0.lock().unwrap().is_none());
    assert!(timer.queue().lock().is_empty());
}
