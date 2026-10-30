use core::time::Duration;

/// How long and how often [`Bench`](super::Bench) measures each routine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BenchConfig {
    /// Time spent running the routine before measuring, to estimate its duration.
    pub warmup: Duration,
    /// Total time spent measuring the samples.
    pub measurement: Duration,
    /// Number of samples; each sample runs the routine many times. Values
    /// outside `1..=BenchConfig::MAXIMUM_SAMPLES` are clamped to that range.
    pub samples: usize,
}

impl BenchConfig {
    /// The largest number of samples measured for one routine.
    pub const MAXIMUM_SAMPLES: usize = 1_000_000;

    /// A short configuration for checking that benchmarks run, not for measuring.
    pub const fn quick() -> BenchConfig {
        BenchConfig { warmup: Duration::from_millis(10), measurement: Duration::from_millis(50), samples: 10 }
    }
}

impl Default for BenchConfig {
    fn default() -> BenchConfig {
        BenchConfig { warmup: Duration::from_millis(500), measurement: Duration::from_secs(2), samples: 50 }
    }
}
