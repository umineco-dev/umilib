//! Benchmarks of `umilib::bytes`.

use std::hint::black_box;

use umilib::bytes::{Buffer, Reader, Writer};
use umilib::platform::bench::{Bench, Throughput};

pub struct Benchmarks;

impl Benchmarks {
    const LENGTH: usize = 4096;

    pub fn run(bench: &mut Bench) {
        let data = vec![0x5Au8; Benchmarks::LENGTH];
        bench.run("bytes-reader-read_be-u32", Some(Throughput::Bytes(Benchmarks::LENGTH as u64)), || {
            let mut reader = Reader::new(black_box(&data));
            let mut sum = 0u32;
            while let Ok(value) = reader.read_be::<u32>() {
                sum = sum.wrapping_add(value);
            }
            black_box(sum);
        });
        bench.run(
            "bytes-reader-read_be_sized-u32-3",
            Some(Throughput::Bytes(Benchmarks::LENGTH as u64 / 3 * 3)),
            || {
                let mut reader = Reader::new(black_box(&data));
                let mut sum = 0u32;
                while let Ok(value) = reader.read_be_sized::<u32>(3) {
                    sum = sum.wrapping_add(value);
                }
                black_box(sum);
            },
        );
        let mut buffer = Buffer::with_capacity(Benchmarks::LENGTH);
        bench.run("bytes-buffer-write_be-u32", Some(Throughput::Bytes(Benchmarks::LENGTH as u64)), || {
            buffer.clear();
            for index in 0..(Benchmarks::LENGTH / 4) as u32 {
                let _ = buffer.write_be(black_box(index));
            }
            black_box(buffer.as_slice());
        });
    }
}
