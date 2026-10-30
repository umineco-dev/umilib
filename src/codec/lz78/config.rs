/// The parameters of an [`LZ78Compressor`](super::LZ78Compressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZ78Config {
    /// B, the base-2 logarithm of the most phrases of the dictionary (1 to
    /// [`LZ78Format::MAXIMUM_BITS`](super::LZ78Format::MAXIMUM_BITS)),
    /// written at the start of the stream.
    pub dictionary_bits: u32,
}

impl Default for LZ78Config {
    fn default() -> LZ78Config {
        LZ78Config { dictionary_bits: 16 }
    }
}

/// The limits of an [`LZ78Decompressor`](super::LZ78Decompressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZ78DecompressorConfig {
    /// The largest B a stream may ask for: a dictionary of 2^B phrases takes
    /// about 9 × 2^B bytes, and its phrases are at most 2^B bytes long.
    pub maximum_dictionary_bits: u32,
}

impl Default for LZ78DecompressorConfig {
    fn default() -> LZ78DecompressorConfig {
        LZ78DecompressorConfig { maximum_dictionary_bits: 20 }
    }
}
