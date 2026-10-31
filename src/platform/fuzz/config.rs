use core::time::Duration;
use std::path::PathBuf;

/// How [`Fuzzer`](super::Fuzzer) generates inputs and when it stops.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzConfig {
    /// The seed of the mutation engine; the same seed generates the same inputs.
    pub seed: u64,
    /// The maximum length of a generated input.
    pub maximum_length: usize,
    /// Stop after this many inputs, if set. Both limits apply; set this to
    /// `None` to fuzz for [`FuzzConfig::duration`] only.
    pub iterations: Option<u64>,
    /// Stop after this much time, if set.
    pub duration: Option<Duration>,
    /// A directory of inputs to start from and to add interesting inputs to.
    pub corpus: Option<PathBuf>,
    /// A directory where failing inputs are saved.
    pub crashes: Option<PathBuf>,
    /// Generated inputs are kept in memory, as material for later
    /// mutations, only while the inputs in memory (those loaded from the
    /// corpus included) are fewer than this.
    pub maximum_corpus_inputs: usize,
    /// About one generated input in this many is kept in memory (at
    /// random); 0 keeps none.
    pub sample_interval: usize,
}

impl Default for FuzzConfig {
    fn default() -> FuzzConfig {
        FuzzConfig {
            seed: 0x756D_696C_6962,
            maximum_length: 4096,
            iterations: Some(100_000),
            duration: None,
            corpus: None,
            crashes: None,
            maximum_corpus_inputs: 1024,
            sample_interval: 64,
        }
    }
}
