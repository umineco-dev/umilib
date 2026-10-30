//! Benchmarks of `umilib::secret`.

use std::hint::black_box;

use umilib::platform::bench::{Bench, Throughput};
use umilib::secret::{ConstantTimeEq, Zeroize};

pub struct Benchmarks;

impl Benchmarks {
    pub fn run(bench: &mut Bench) {
        let (a, b) = ([7u8; 32], [7u8; 32]);
        bench.run("secret-constant_time_eq-32", Some(Throughput::Bytes(32)), || {
            black_box(black_box(&a[..]).ct_eq(black_box(&b[..])));
        });
        let mut data = vec![0xAAu8; 4096];
        bench.run("secret-zeroize-4096", Some(Throughput::Bytes(4096)), || {
            black_box(&mut data[..]).zeroize();
        });
    }
}
