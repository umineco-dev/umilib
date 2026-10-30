//! Measuring how long code takes to run.
//!
//! [`Bench`] runs each routine during a warm-up period to estimate its
//! duration, then measures a number of samples of many iterations each and
//! summarizes them as [`Statistics`]. Results can be printed as text or JSON.

mod arguments;
#[allow(clippy::module_inception)]
mod bench;
mod config;
mod result;
mod statistics;
mod throughput;

pub use arguments::BenchArguments;
pub use bench::Bench;
pub use config::BenchConfig;
pub use result::BenchResult;
pub use statistics::Statistics;
pub use throughput::Throughput;
