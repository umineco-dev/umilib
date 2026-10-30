/// The parameters of a [`BrotliCompressor`](super::BrotliCompressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrotliConfig {
    /// 0 to 11: the search of matches ([`BrotliLevel`](super::BrotliLevel)).
    pub level: u32,
    /// WBITS, the base-2 logarithm of the window (10 to 24): matches reach
    /// back 2^WBITS - 16 bytes, and a decompressor keeps that much history.
    pub window_bits: u32,
}

impl Default for BrotliConfig {
    fn default() -> BrotliConfig {
        BrotliConfig { level: 6, window_bits: 22 }
    }
}

/// The limits of a [`BrotliDecompressor`](super::BrotliDecompressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrotliDecompressorConfig {
    /// The largest WBITS a stream may ask for (10 to 24; larger ones fail
    /// with `LimitExceeded`): 24 by default, the largest of the format, so
    /// that every stream decodes; the history grows with the data up to
    /// 2^WBITS - 16 bytes.
    pub maximum_window_bits: u32,
}

impl Default for BrotliDecompressorConfig {
    fn default() -> BrotliDecompressorConfig {
        BrotliDecompressorConfig { maximum_window_bits: 24 }
    }
}
