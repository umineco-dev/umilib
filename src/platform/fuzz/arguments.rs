use core::time::Duration;
use std::string::String;
use std::vec::Vec;

/// The engine that generates inputs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FuzzEngine {
    /// The built-in mutation engine of [`Fuzzer`](super::Fuzzer).
    #[default]
    Builtin,
    /// LLVM libFuzzer, available when built by `tools/fuzz.py`.
    LibFuzzer,
}

/// Command-line arguments of a fuzzing program.
///
/// Without `--fuzz`, the program replays the stored corpus of every target
/// whose name contains `filter` (all targets without a filter) and none of the
/// `--skip` texts, which is what `cargo test` runs; `--list` lists the targets
/// instead, one `<name>: test` line each, as test runners expect. `--fuzz
/// NAME` fuzzes one target; `--engine`, `--time SECONDS`, `--iterations
/// COUNT`, `--seed SEED` and `--maximum-length BYTES` configure it, and
/// arguments after `--` are passed to libFuzzer. Other flags of the standard
/// test harness (`--quiet`, `--test-threads N`, `--format F`, ...) are ignored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FuzzArguments {
    pub filter: Option<String>,
    pub skip: Vec<String>,
    pub list: bool,
    pub fuzz: Option<String>,
    pub engine: FuzzEngine,
    pub duration: Option<Duration>,
    pub iterations: Option<u64>,
    pub seed: Option<u64>,
    pub maximum_length: Option<usize>,
    pub engine_arguments: Vec<String>,
}

impl FuzzArguments {
    /// Flags of the standard test harness that are accepted and ignored.
    pub const IGNORED: [&'static str; 8] =
        ["--quiet", "-q", "--nocapture", "--show-output", "--exact", "--ignored", "--include-ignored", "--test"];
    /// Flags of the standard test harness that take a value, accepted and ignored with it.
    pub const IGNORED_WITH_VALUE: [&'static str; 4] = ["--test-threads", "--format", "--color", "-Z"];

    /// Parses `arguments`, which do not include the program name.
    pub fn parse(arguments: impl IntoIterator<Item = String>) -> Result<FuzzArguments, String> {
        let mut parsed = FuzzArguments::default();
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let mut value = |name: &str| arguments.next().ok_or_else(|| std::format!("{name} requires a value"));
            match argument.as_str() {
                "--" => {
                    parsed.engine_arguments.extend(arguments);
                    break;
                }
                "--fuzz" => parsed.fuzz = Some(value("--fuzz")?),
                "--list" => parsed.list = true,
                "--skip" => parsed.skip.push(value("--skip")?),
                flag if FuzzArguments::IGNORED_WITH_VALUE.contains(&flag) => {
                    value(flag)?;
                }
                "--engine" => {
                    parsed.engine = match value("--engine")?.as_str() {
                        "builtin" => FuzzEngine::Builtin,
                        "libfuzzer" => FuzzEngine::LibFuzzer,
                        other => return Err(std::format!("unknown engine: {other}")),
                    }
                }
                "--time" => {
                    let seconds: u64 = value("--time")?.parse().map_err(|_| String::from("--time requires seconds"))?;
                    parsed.duration = Some(Duration::from_secs(seconds));
                }
                "--iterations" => {
                    parsed.iterations = Some(
                        value("--iterations")?.parse().map_err(|_| String::from("--iterations requires a count"))?,
                    )
                }
                "--seed" => {
                    parsed.seed = Some(value("--seed")?.parse().map_err(|_| String::from("--seed requires a number"))?)
                }
                "--maximum-length" => {
                    parsed.maximum_length = Some(
                        value("--maximum-length")?
                            .parse()
                            .map_err(|_| String::from("--maximum-length requires bytes"))?,
                    )
                }
                flag if FuzzArguments::IGNORED.contains(&flag)
                    || FuzzArguments::IGNORED_WITH_VALUE
                        .iter()
                        .any(|name| flag.starts_with(&std::format!("{name}="))) => {}
                flag if flag.starts_with('-') => return Err(std::format!("unknown argument: {flag}")),
                filter => {
                    if parsed.filter.is_some() {
                        return Err(std::format!("unexpected argument: {filter}"));
                    }
                    parsed.filter = Some(String::from(filter));
                }
            }
        }
        Ok(parsed)
    }
}
