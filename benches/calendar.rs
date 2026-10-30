//! Benchmarks of `umilib::calendar`: dates to days and back.

use std::hint::black_box;

use umilib::calendar::Date;
use umilib::platform::bench::{Bench, Throughput};

pub struct Benchmarks;

impl Benchmarks {
    pub fn run(bench: &mut Bench) {
        let date = Date::new(2026, 10, 30).expect("a date");
        bench.run("calendar-days", Some(Throughput::Elements(1)), || {
            black_box(black_box(date).days());
        });
        let days = date.days();
        bench.run("calendar-from-days", Some(Throughput::Elements(1)), || {
            black_box(Date::from_days(black_box(days)));
        });
    }
}
