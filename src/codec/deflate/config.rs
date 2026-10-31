use crate::codec::CompressionError;

/// The parameters of a [`DeflateCompressor`](super::DeflateCompressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeflateConfig {
    /// 0 (stored blocks, no compression) to 9 (the most effort), with the
    /// search parameters of zlib's levels.
    pub level: u32,
    /// The base-2 logarithm of the window (8 to 15): matches reach at most
    /// 2^window_bits bytes back (what a zlib header announces).
    pub window_bits: u32,
}

impl DeflateConfig {
    pub const MAXIMUM_LEVEL: u32 = 9;

    pub fn check(&self) -> Result<(), CompressionError> {
        if self.level <= DeflateConfig::MAXIMUM_LEVEL && (8..=15).contains(&self.window_bits) {
            Ok(())
        } else {
            Err(CompressionError::InvalidParameter)
        }
    }
}

impl Default for DeflateConfig {
    fn default() -> DeflateConfig {
        DeflateConfig { level: 6, window_bits: 15 }
    }
}

/// The search parameters of a level, those of zlib's configuration table:
/// matches at least `good_length` long reduce the search for a longer one
/// (lazy matching) to a quarter; a match shorter than `lazy_length` is
/// compared with the match at the next position (or, for greedy levels, no
/// match is deferred); `nice_length` ends a search; `chain_limit` bounds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeflateLevel {
    pub good_length: usize,
    pub lazy_length: usize,
    pub nice_length: usize,
    pub chain_limit: usize,
    pub lazy: bool,
}

impl DeflateLevel {
    /// The parameters of the levels 0 to 9.
    pub const LEVELS: [DeflateLevel; 10] = [
        DeflateLevel { good_length: 0, lazy_length: 0, nice_length: 0, chain_limit: 0, lazy: false },
        DeflateLevel { good_length: 4, lazy_length: 4, nice_length: 8, chain_limit: 4, lazy: false },
        DeflateLevel { good_length: 4, lazy_length: 5, nice_length: 16, chain_limit: 8, lazy: false },
        DeflateLevel { good_length: 4, lazy_length: 6, nice_length: 32, chain_limit: 32, lazy: false },
        DeflateLevel { good_length: 4, lazy_length: 4, nice_length: 16, chain_limit: 16, lazy: true },
        DeflateLevel { good_length: 8, lazy_length: 16, nice_length: 32, chain_limit: 32, lazy: true },
        DeflateLevel { good_length: 8, lazy_length: 16, nice_length: 128, chain_limit: 128, lazy: true },
        DeflateLevel { good_length: 8, lazy_length: 32, nice_length: 128, chain_limit: 256, lazy: true },
        DeflateLevel { good_length: 32, lazy_length: 128, nice_length: 258, chain_limit: 1024, lazy: true },
        DeflateLevel { good_length: 32, lazy_length: 258, nice_length: 258, chain_limit: 4096, lazy: true },
    ];
}

/// The limits of a [`DeflateDecompressor`](super::DeflateDecompressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeflateDecompressorConfig {
    /// The base-2 logarithm of the window kept (8 to 15): a match reaching
    /// farther back fails with `LimitExceeded`. Streams of other compressors
    /// may use the whole window of 32 KiB (15).
    pub window_bits: u32,
}

impl Default for DeflateDecompressorConfig {
    fn default() -> DeflateDecompressorConfig {
        DeflateDecompressorConfig { window_bits: 15 }
    }
}
