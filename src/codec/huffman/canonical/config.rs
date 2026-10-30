/// The parameters of a [`CanonicalHuffmanCompressor`](super::CanonicalHuffmanCompressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalHuffmanConfig {
    /// The most input bytes of a block, at least 1: the code of each block
    /// fits its bytes, so smaller blocks follow changes of the data more
    /// closely and larger ones spend less on code lengths (129 bytes a block).
    pub block_size: usize,
}

impl Default for CanonicalHuffmanConfig {
    fn default() -> CanonicalHuffmanConfig {
        CanonicalHuffmanConfig { block_size: 1 << 16 }
    }
}
