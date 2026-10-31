//! The fuzz targets of umilib, one module per tested module.
//!
//! `cargo test` replays the corpus in `fuzz/corpus/<target>` and runs a short,
//! deterministic built-in fuzzing pass over every target. See `docs/fuzz.md`
//! for long runs and libFuzzer.

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

use std::path::PathBuf;
use std::process::ExitCode;

use umilib::platform::fuzz::{Corpus, FuzzArguments, FuzzConfig, FuzzEngine, FuzzTarget, Fuzzer};

/// The registry of fuzz targets and the program that runs them.
struct Targets;

impl Targets {
    /// The number of inputs of the deterministic pass run by `cargo test`.
    const SMOKE_ITERATIONS: u64 = 2_000;

    fn all() -> Vec<&'static dyn FuzzTarget> {
        let groups: &[&[&'static dyn FuzzTarget]] = &[
            #[cfg(umilib_feature = "auth")]
            auth::TARGETS,
            #[cfg(umilib_feature = "bytes")]
            bytes::TARGETS,
            #[cfg(umilib_feature = "calendar")]
            calendar::TARGETS,
            #[cfg(umilib_feature = "codec")]
            codec::TARGETS,
            #[cfg(umilib_feature = "crypto")]
            crypto::TARGETS,
            #[cfg(umilib_feature = "hash")]
            hash::TARGETS,
            #[cfg(umilib_feature = "math")]
            math::TARGETS,
            #[cfg(umilib_feature = "platform")]
            platform::TARGETS,
            #[cfg(umilib_feature = "protocol")]
            protocol::TARGETS,
            #[cfg(umilib_feature = "runtime")]
            runtime::TARGETS,
            #[cfg(umilib_feature = "service")]
            service::TARGETS,
            #[cfg(umilib_feature = "secret")]
            secret::TARGETS,
        ];
        groups.iter().flat_map(|group| group.iter().copied()).collect()
    }

    fn directory(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz").join(name)
    }

    fn selected(arguments: &FuzzArguments) -> Vec<&'static dyn FuzzTarget> {
        Targets::all()
            .into_iter()
            .filter(|target| arguments.filter.as_deref().is_none_or(|filter| target.name().contains(filter)))
            .filter(|target| !arguments.skip.iter().any(|skip| target.name().contains(skip.as_str())))
            .collect()
    }

    fn list(arguments: &FuzzArguments) -> ExitCode {
        for target in Targets::selected(arguments) {
            println!("{}: test", target.name());
        }
        ExitCode::SUCCESS
    }

    fn replay(arguments: &FuzzArguments) -> ExitCode {
        let mut failed = false;
        let mut count = 0;
        for target in Targets::selected(arguments) {
            count += 1;
            let corpus = match Corpus::load(&Targets::directory("corpus").join(target.name())) {
                Ok(corpus) => corpus,
                Err(error) => {
                    eprintln!("{}: cannot read the corpus: {error}", target.name());
                    failed = true;
                    continue;
                }
            };
            let replay = Fuzzer::default().replay(target, &corpus);
            let config = FuzzConfig { iterations: Some(Targets::SMOKE_ITERATIONS), ..FuzzConfig::default() };
            let smoke = match Fuzzer::new(config).run(target) {
                Ok(report) => report,
                Err(error) => {
                    eprintln!("{}: {error}", target.name());
                    failed = true;
                    continue;
                }
            };
            let passed = replay.is_success() && smoke.is_success();
            println!(
                "fuzz {} ... {} ({} corpus inputs, {} generated)",
                target.name(),
                if passed { "ok" } else { "FAILED" },
                replay.iterations,
                smoke.iterations
            );
            for input in replay.failures.iter().chain(&smoke.failures) {
                println!("    failing input: {input:02x?}");
            }
            failed |= !passed;
        }
        println!("\nfuzz result: {}. {count} targets", if failed { "FAILED" } else { "ok" });
        if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS }
    }

    fn fuzz(name: &str, arguments: &FuzzArguments) -> ExitCode {
        let Some(target) = Targets::all().into_iter().find(|target| target.name() == name) else {
            eprintln!("unknown fuzz target: {name}");
            return ExitCode::FAILURE;
        };
        match arguments.engine {
            FuzzEngine::Builtin => {
                let defaults = FuzzConfig::default();
                let config = FuzzConfig {
                    seed: arguments.seed.unwrap_or(defaults.seed),
                    maximum_length: arguments.maximum_length.unwrap_or(defaults.maximum_length),
                    iterations: if arguments.duration.is_some() {
                        arguments.iterations
                    } else {
                        arguments.iterations.or(defaults.iterations)
                    },
                    duration: arguments.duration,
                    corpus: Some(Targets::directory("corpus").join(name)),
                    crashes: Some(Targets::directory("crashes")),
                    ..defaults
                };
                match Fuzzer::new(config).run(target) {
                    Ok(report) => {
                        println!("{name}: {} inputs in {:?}", report.iterations, report.elapsed);
                        for input in &report.failures {
                            println!("failing input: {input:02x?}");
                        }
                        for path in &report.saved {
                            println!("saved to {}", path.display());
                        }
                        if report.is_success() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
                    }
                    Err(error) => {
                        eprintln!("{name}: {error}");
                        ExitCode::FAILURE
                    }
                }
            }
            FuzzEngine::LibFuzzer => Targets::lib_fuzzer(target, arguments),
        }
    }

    /// Runs the target named by `LibFuzzer::TARGET_VARIABLE` under libFuzzer
    /// with this process's arguments, which are libFuzzer's.
    #[cfg(umilib_libfuzzer)]
    fn lib_fuzzer_child(name: &str) -> ExitCode {
        let Some(target) = Targets::all().into_iter().find(|target| target.name() == name) else {
            eprintln!("unknown fuzz target: {name}");
            return ExitCode::FAILURE;
        };
        let program = std::env::current_exe().map(|path| path.to_string_lossy().into_owned()).unwrap_or_default();
        let arguments: Vec<String> = std::env::args().skip(1).collect();
        match umilib::platform::fuzz::LibFuzzer::run(target, &program, &arguments) {
            Ok(0) => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        }
    }

    #[cfg(umilib_libfuzzer)]
    fn lib_fuzzer(target: &'static dyn FuzzTarget, arguments: &FuzzArguments) -> ExitCode {
        let corpus = Targets::directory("corpus").join(target.name());
        let _ = std::fs::create_dir_all(&corpus);
        let mut engine = arguments.engine_arguments.clone();
        if let Some(duration) = arguments.duration {
            engine.push(format!("-max_total_time={}", duration.as_secs()));
        }
        if let Some(iterations) = arguments.iterations {
            engine.push(format!("-runs={iterations}"));
        }
        if let Some(length) = arguments.maximum_length {
            engine.push(format!("-max_len={length}"));
        }
        engine.push(corpus.to_string_lossy().into_owned());
        // Re-run this program as a libFuzzer process for the target, so that the
        // processes libFuzzer itself starts run the same target.
        let program = match std::env::current_exe() {
            Ok(program) => program,
            Err(error) => {
                eprintln!("cannot find this program: {error}");
                return ExitCode::FAILURE;
            }
        };
        let status = std::process::Command::new(program)
            .env(umilib::platform::fuzz::LibFuzzer::TARGET_VARIABLE, target.name())
            .args(&engine)
            .status();
        match status {
            Ok(status) if status.success() => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(error) => {
                eprintln!("cannot start libFuzzer: {error}");
                ExitCode::FAILURE
            }
        }
    }

    #[cfg(not(umilib_libfuzzer))]
    fn lib_fuzzer(_: &'static dyn FuzzTarget, _: &FuzzArguments) -> ExitCode {
        eprintln!("this build has no libFuzzer; run it with tools/fuzz.py");
        ExitCode::FAILURE
    }
}

fn main() -> ExitCode {
    #[cfg(umilib_libfuzzer)]
    if let Some(name) = umilib::platform::fuzz::LibFuzzer::requested_target() {
        return Targets::lib_fuzzer_child(&name);
    }
    let arguments = match FuzzArguments::parse(std::env::args().skip(1)) {
        Ok(arguments) => arguments,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    match &arguments.fuzz {
        Some(name) => Targets::fuzz(name, &arguments),
        None if arguments.list => Targets::list(&arguments),
        None => Targets::replay(&arguments),
    }
}
