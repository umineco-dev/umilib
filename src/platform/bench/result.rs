use std::string::String;

use super::{Statistics, Throughput};

/// The measurement of one routine.
#[derive(Clone, Debug, PartialEq)]
pub struct BenchResult {
    pub name: String,
    /// Iterations run in each sample.
    pub iterations: u64,
    pub samples: usize,
    pub statistics: Statistics,
    pub throughput: Option<Throughput>,
}

impl BenchResult {
    /// The work done per second at the median duration, if a throughput was given.
    pub fn throughput_per_second(&self) -> Option<f64> {
        let throughput = self.throughput?;
        if self.statistics.median <= 0.0 {
            return None;
        }
        Some(throughput.amount() as f64 * 1e9 / self.statistics.median)
    }
}
