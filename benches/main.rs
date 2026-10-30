//! The benchmarks of umilib, one module per measured module.
//!
//! `cargo bench --features <features>` runs them; `cargo bench -- --quick`
//! only checks that they run, and `--json PATH` saves the results.

#[cfg(umilib_feature = "auth")]
mod auth;
#[cfg(umilib_feature = "bytes")]
mod bytes;
#[cfg(umilib_feature = "calendar")]
mod calendar;
#[cfg(umilib_feature = "codec")]
mod codec;
#[cfg(umilib_feature = "crypto")]
mod crypto;
#[cfg(umilib_feature = "hash")]
mod hash;
#[cfg(umilib_feature = "math")]
mod math;
#[cfg(umilib_feature = "platform")]
mod platform;
#[cfg(umilib_feature = "protocol")]
mod protocol;
#[cfg(umilib_feature = "runtime")]
mod runtime;
#[cfg(umilib_feature = "secret")]
mod secret;
#[cfg(umilib_feature = "service")]
mod service;

use std::process::ExitCode;

use umilib::platform::bench::{Bench, BenchArguments, BenchConfig};

fn main() -> ExitCode {
    let arguments = match BenchArguments::parse(std::env::args().skip(1)) {
        Ok(arguments) => arguments,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let mut bench = Bench::new(if arguments.quick { BenchConfig::quick() } else { BenchConfig::default() });
    bench.set_filter(arguments.filter.clone());
    #[cfg(umilib_feature = "auth")]
    auth::Benchmarks::run(&mut bench);
    #[cfg(umilib_feature = "bytes")]
    bytes::Benchmarks::run(&mut bench);
    #[cfg(umilib_feature = "calendar")]
    calendar::Benchmarks::run(&mut bench);
    #[cfg(umilib_feature = "codec")]
    codec::Benchmarks::run(&mut bench);
    #[cfg(umilib_feature = "crypto")]
    crypto::Benchmarks::run(&mut bench);
    #[cfg(umilib_feature = "hash")]
    hash::Benchmarks::run(&mut bench);
    #[cfg(umilib_feature = "math")]
    math::Benchmarks::run(&mut bench);
    #[cfg(umilib_feature = "platform")]
    platform::Benchmarks::run(&mut bench);
    #[cfg(umilib_feature = "protocol")]
    protocol::Benchmarks::run(&mut bench);
    #[cfg(umilib_feature = "runtime")]
    runtime::Benchmarks::run(&mut bench);
    #[cfg(umilib_feature = "service")]
    service::Benchmarks::run(&mut bench);
    #[cfg(umilib_feature = "secret")]
    secret::Benchmarks::run(&mut bench);
    print!("{}", bench.report_text());
    if let Some(path) = &arguments.json
        && let Err(error) = std::fs::write(path, bench.report_json())
    {
        eprintln!("cannot write {}: {error}", path.display());
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
