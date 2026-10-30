/// The parameters of an [`LZ77Compressor`](super::LZ77Compressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZ77Config {
    /// The most candidates examined for each match (1 or more): more find
    /// longer matches, more slowly.
    pub chain_limit: usize,
}

impl Default for LZ77Config {
    fn default() -> LZ77Config {
        LZ77Config { chain_limit: 64 }
    }
}
