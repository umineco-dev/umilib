//! Benchmarks of `umilib::runtime`: spawning and polling tasks, wakes, channels and timers.

use std::hint::black_box;

use umilib::platform::bench::{Bench, Throughput};
use umilib::runtime::{Channel, Executor, Instant, LocalExecutor, TimerQueue, YieldNow};

pub struct Benchmarks;

impl Benchmarks {
    pub fn run(bench: &mut Bench) {
        let executor = LocalExecutor::new();
        bench.run("runtime-spawn-run-1000", Some(Throughput::Elements(1000)), || {
            for index in 0..1000u32 {
                drop(executor.spawn(async move { black_box(index) }));
            }
            executor.run_until_idle();
        });
        bench.run("runtime-yield-1000", Some(Throughput::Elements(1000)), || {
            drop(executor.spawn(async {
                for _ in 0..1000 {
                    YieldNow::new().await;
                }
            }));
            executor.run_until_idle();
        });
        bench.run("runtime-channel-10000", Some(Throughput::Elements(10_000)), || {
            let (sender, mut receiver) = Channel::bounded::<u64>(64);
            let producer = executor.spawn(async move {
                for value in 0..10_000u64 {
                    sender.send(value).await.unwrap();
                }
            });
            let consumer = executor.spawn(async move {
                let mut sum = 0u64;
                while let Some(value) = receiver.receive().await {
                    sum += value;
                }
                sum
            });
            executor.run_until_idle();
            drop(producer);
            black_box(consumer);
        });
        bench.run("runtime-timer-queue-1000", Some(Throughput::Elements(1000)), || {
            let mut queue = TimerQueue::new();
            for index in 0..1000u64 {
                queue.insert(Instant::from_nanos(index.wrapping_mul(7919) % 1000), None);
            }
            black_box(queue.fire(Instant::MAX));
        });
    }
}
