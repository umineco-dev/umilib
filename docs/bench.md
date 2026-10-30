# Benchmarks

`umilib::platform::bench` (feature `platform-bench`) measures code. It is a
general library: use it for your own code too.

```rust
use std::hint::black_box;
use umilib::platform::bench::{Bench, BenchConfig, Throughput};

let mut bench = Bench::new(BenchConfig::default());
let data = vec![0u8; 4096];
bench.run("checksum-4096", Some(Throughput::Bytes(4096)), || {
    black_box(black_box(&data).iter().map(|&byte| byte as u32).sum::<u32>());
});
print!("{}", bench.report_text());
```

Each routine runs for `warmup` to estimate its duration, then `samples` samples
of equal iteration counts fill `measurement`. Results report the median and the
median absolute deviation (robust against outliers), as well as mean, standard
deviation, minimum and maximum, all in nanoseconds per iteration.

## umilib's benchmarks

`benches/` holds one module per measured module:

```bash
cargo bench --all-features                       # measure everything
cargo bench --all-features -- bytes              # names containing "bytes"
cargo bench --all-features -- --quick            # only check that they run
cargo bench --all-features -- --json results.json
```

The `Bench` workflow runs them on demand on every CI platform and uploads the
JSON results. CI machines are noisy; compare results from the same machine.
