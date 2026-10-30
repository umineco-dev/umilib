use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use umilib::service::{
    AndRule, AnyRule, BoxService, DynService, FunctionRule, FunctionService, NotRule, OrRule, Rule, Service,
};

use crate::{YieldOnce, block_on};

/// A service that counts its calls.
struct Counter(AtomicUsize);

impl Service<u32> for Counter {
    type Response = usize;
    type Error = Infallible;

    async fn call(&self, request: u32) -> Result<usize, Infallible> {
        YieldOnce::new().await;
        Ok(self.0.fetch_add(request as usize, Ordering::Relaxed) + request as usize)
    }
}

#[test]
fn services_are_shared_through_references_boxes_and_arcs() {
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    assert_eq!(block_on(counter.call(1)), Ok(1));
    let reference: &Counter = &counter;
    assert_eq!(block_on(Service::call(&reference, 2)), Ok(3));
    assert_eq!(block_on(Box::new(&*counter).call(3)), Ok(6));
    assert_eq!(block_on(Service::call(&counter, 4)), Ok(10));
}

#[test]
fn function_services_call_their_function() {
    let double = FunctionService::new(|value: u32| async move { Ok::<u32, Infallible>(value * 2) });
    assert_eq!(block_on(double.call(21)), Ok(42));
    let fallible = FunctionService::new(|value: u32| async move { 100u32.checked_div(value).ok_or("zero") });
    assert_eq!(block_on(fallible.call(0)), Err("zero"));
    assert_eq!(block_on(fallible.call(5)), Ok(20));
}

#[test]
fn boxed_services_hide_their_type() {
    let services: Vec<BoxService<u32, usize, Infallible>> = vec![
        BoxService::new(Counter(AtomicUsize::new(100))),
        BoxService::new(FunctionService::new(|value: u32| async move { Ok(value as usize) })),
    ];
    let answers: Vec<_> = services.iter().map(|service| block_on(service.call(7))).collect();
    assert_eq!(answers, vec![Ok(107), Ok(7)]);
    let dynamic: &dyn DynService<u32, Response = usize, Error = Infallible> = &Counter(AtomicUsize::new(1));
    assert_eq!(block_on(dynamic.call_boxed(1)), Ok(2));
}

#[test]
fn service_futures_are_send_and_run_on_other_threads() {
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let counter = counter.clone();
            std::thread::spawn(move || {
                for _ in 0..1000 {
                    block_on(counter.call(1)).unwrap();
                }
            })
        })
        .collect();
    threads.into_iter().for_each(|thread| thread.join().unwrap());
    assert_eq!(block_on(counter.call(0)), Ok(8000));
    // A service future can be sent to another thread before it is polled.
    fn assert_send<T: Send>(value: T) -> T {
        value
    }
    let future = assert_send(counter.call(1));
    std::thread::scope(|scope| assert_eq!(scope.spawn(move || block_on(future)).join().unwrap(), Ok(8001)));
}

#[test]
fn rules_combine() {
    let even = FunctionRule::new(|value: &u32| value.is_multiple_of(2));
    let small = FunctionRule::new(|value: &u32| *value < 10);
    let both = AndRule::new(even, small);
    let either = OrRule::new(even, small);
    let odd = NotRule::new(even);
    let truth = |rule: &dyn Rule<u32>| (0..20).filter(|value| rule.matches(value)).collect::<Vec<u32>>();
    assert_eq!(truth(&both), vec![0, 2, 4, 6, 8]);
    assert_eq!(truth(&either), vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 18]);
    assert_eq!(truth(&odd), (0..20).filter(|value: &u32| !value.is_multiple_of(2)).collect::<Vec<_>>());
    assert_eq!(truth(&AnyRule), (0..20).collect::<Vec<_>>());
    // The methods build the same rules.
    assert_eq!(truth(&even.and(small)), truth(&both));
    assert_eq!(truth(&even.or(small)), truth(&either));
    assert_eq!(truth(&even.not()), truth(&odd));
    // `and` does not ask its second rule if the first does not match, nor `or` if it does.
    let asked = AtomicUsize::new(0);
    let counting = FunctionRule::new(|_: &u32| {
        asked.fetch_add(1, Ordering::Relaxed);
        true
    });
    assert!(!FunctionRule::new(|_: &u32| false).and(&counting).matches(&0));
    assert!(FunctionRule::new(|_: &u32| true).or(&counting).matches(&0));
    assert_eq!(asked.load(Ordering::Relaxed), 0);
}
