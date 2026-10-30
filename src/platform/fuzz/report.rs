use core::time::Duration;
use std::path::PathBuf;
use std::vec::Vec;

/// The outcome of a fuzzing or replay run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FuzzReport {
    /// The number of inputs run.
    pub iterations: u64,
    /// The inputs that made the target panic.
    pub failures: Vec<Vec<u8>>,
    /// The files the failing inputs were saved to. A failure is missing here
    /// if it could not be saved; it is still in `failures`.
    pub saved: Vec<PathBuf>,
    pub elapsed: Duration,
}

impl FuzzReport {
    /// Whether every input passed.
    pub fn is_success(&self) -> bool {
        self.failures.is_empty()
    }
}
