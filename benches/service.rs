//! Benchmarks of `umilib::service`: matching patterns and routing requests.

use std::convert::Infallible;
use std::future::Future;
use std::hint::black_box;
use std::pin::pin;
use std::task::{Context, Waker};

use umilib::platform::bench::{Bench, Throughput};
use umilib::service::{FunctionService, Pattern, Router, Service};

pub struct Benchmarks;

impl Benchmarks {
    pub fn run(bench: &mut Bench) {
        let host = Pattern::suffix(b".example.com").ignoring_ascii_case(true);
        bench.run("service-pattern-suffix", Some(Throughput::Elements(1)), || {
            black_box(host.matches_bytes(black_box(b"login.auth.EXAMPLE.com")));
        });
        // 64 routes; the request matches the last one.
        let mut router = Router::new();
        for index in 0..64 {
            let path = format!("/service-{index}/");
            router.push(
                Pattern::prefix(path.as_bytes()),
                FunctionService::new(|request: Vec<u8>| async move { Ok::<usize, Infallible>(request.len()) }),
            );
        }
        let request = b"/service-63/resource".to_vec();
        bench.run("service-router-64-routes", Some(Throughput::Elements(1)), || {
            let mut future = pin!(router.call(black_box(request.clone())));
            assert!(black_box(future.as_mut().poll(&mut Context::from_waker(Waker::noop()))).is_ready());
        });
    }
}
