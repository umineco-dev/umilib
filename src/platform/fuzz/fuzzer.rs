use std::panic::{self, AssertUnwindSafe};
use std::time::Instant;
use std::vec::Vec;

use super::{Corpus, FuzzConfig, FuzzReport, FuzzTarget, Mutator};

/// Runs a [`FuzzTarget`] with the built-in mutation engine.
///
/// The engine does not observe coverage: it mutates corpus inputs at random
/// and stops at the first failure. Use `LibFuzzer` (built with the `umilib_libfuzzer` cfg) for
/// coverage-guided fuzzing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fuzzer {
    config: FuzzConfig,
}

impl Fuzzer {
    /// Creates a fuzzer with `config`.
    pub fn new(config: FuzzConfig) -> Fuzzer {
        Fuzzer { config }
    }

    /// The configuration of the fuzzer.
    pub fn config(&self) -> &FuzzConfig {
        &self.config
    }

    /// Runs `target` on `input` and reports whether it returned without panicking.
    pub fn check(target: &dyn FuzzTarget, input: &[u8]) -> bool {
        panic::catch_unwind(AssertUnwindSafe(|| target.run(input))).is_ok()
    }

    /// Runs `target` on every input of `corpus`, reporting each failing input.
    pub fn replay(&self, target: &dyn FuzzTarget, corpus: &Corpus) -> FuzzReport {
        let start = Instant::now();
        let mut report = FuzzReport::default();
        for input in &corpus.inputs {
            report.iterations += 1;
            if !Fuzzer::check(target, input) {
                report.failures.push(input.clone());
            }
        }
        report.elapsed = start.elapsed();
        report
    }

    /// Whether `name` can name a directory: ASCII letters, digits, `-`, `_` and
    /// `.`, not starting with `.`.
    pub fn is_valid_name(name: &str) -> bool {
        !name.is_empty()
            && !name.starts_with('.')
            && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    }

    /// Fuzzes `target` until the configured number of iterations or duration
    /// is reached (whichever comes first), or until the first failure, which is
    /// saved to `<crashes>/<target name>/` if a crash directory is configured.
    ///
    /// Fails if the target name is not [valid](Fuzzer::is_valid_name) or the
    /// corpus cannot be read. Failing to save a failure is reported by
    /// [`FuzzReport::saved`] instead.
    pub fn run(&self, target: &dyn FuzzTarget) -> std::io::Result<FuzzReport> {
        if !Fuzzer::is_valid_name(target.name()) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid fuzz target name"));
        }
        let mut corpus = match &self.config.corpus {
            Some(directory) => Corpus::load(directory)?,
            None => Corpus::default(),
        };
        if corpus.inputs.is_empty() {
            corpus.inputs.push(Vec::new());
        }
        let mut mutator = Mutator::new(self.config.seed);
        let start = Instant::now();
        let mut report = FuzzReport::default();
        let mut input = Vec::new();
        loop {
            if self.config.iterations.is_some_and(|limit| report.iterations >= limit)
                || self.config.duration.is_some_and(|limit| start.elapsed() >= limit)
            {
                break;
            }
            input.clear();
            input.extend_from_slice(&corpus.inputs[mutator.below(corpus.inputs.len())]);
            mutator.mutate(&mut input, self.config.maximum_length, &corpus.inputs);
            report.iterations += 1;
            if !Fuzzer::check(target, &input) {
                report.failures.push(input.clone());
                if let Some(directory) = &self.config.crashes
                    && let Ok(path) = Corpus::save(&directory.join(target.name()), &input)
                {
                    report.saved.push(path);
                }
                break;
            }
            // Keep a bounded sample of generated inputs as material for later mutations.
            if corpus.inputs.len() < self.config.maximum_corpus_inputs
                && self.config.sample_interval != 0
                && mutator.below(self.config.sample_interval) == 0
            {
                corpus.inputs.push(input.clone());
            }
        }
        report.elapsed = start.elapsed();
        Ok(report)
    }
}
