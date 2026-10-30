//! Fuzzing: running code on many generated inputs to find inputs that make it panic.
//!
//! A [`FuzzTarget`] fails by panicking. [`Fuzzer`] drives targets with its
//! own mutation engine, which needs nothing but `std`, and replays stored
//! inputs as regression tests. With the `umilib_libfuzzer` cfg (set by
//! `tools/fuzz.py`), `LibFuzzer` runs targets under LLVM's coverage-guided
//! libFuzzer instead.

mod arguments;
mod config;
mod corpus;
mod function;
#[allow(clippy::module_inception)]
mod fuzzer;
#[cfg(umilib_libfuzzer)]
mod lib_fuzzer;
mod mutator;
mod report;
mod target;

pub use arguments::{FuzzArguments, FuzzEngine};
pub use config::FuzzConfig;
pub use corpus::Corpus;
pub use function::FuzzFunction;
pub use fuzzer::Fuzzer;
#[cfg(umilib_libfuzzer)]
pub use lib_fuzzer::LibFuzzer;
pub use mutator::Mutator;
pub use report::FuzzReport;
pub use target::FuzzTarget;
