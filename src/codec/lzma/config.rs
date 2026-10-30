use super::LZMAProperties;

/// The parameters of an [`LZMACompressor`](super::LZMACompressor) (.lzma
/// files) or an [`LZMA2Compressor`](super::LZMA2Compressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZMAConfig {
    /// 0 to 9: the search ([`LZMALevel`](super::LZMALevel)) and, unless
    /// `dictionary_size` is given, the dictionary of xz's preset of that level.
    pub level: u32,
    pub properties: LZMAProperties,
    /// The dictionary size (4 KiB to 1.5 GiB), if not that of the level.
    pub dictionary_size: Option<usize>,
    /// For .lzma files: the size of the data, written in the header; the
    /// stream then has no end marker, and finishing a stream of another size
    /// fails with `InvalidParameter`. Unknown by default (an end marker).
    pub uncompressed_size: Option<u64>,
}

impl Default for LZMAConfig {
    fn default() -> LZMAConfig {
        LZMAConfig { level: 6, properties: LZMAProperties::default(), dictionary_size: None, uncompressed_size: None }
    }
}

/// The limits of an [`LZMADecompressor`](super::LZMADecompressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZMADecompressorConfig {
    /// The largest dictionary a stream may ask for (larger ones fail with
    /// `LimitExceeded`); the window grows with the data up to it.
    pub maximum_dictionary_size: usize,
}

impl Default for LZMADecompressorConfig {
    fn default() -> LZMADecompressorConfig {
        LZMADecompressorConfig { maximum_dictionary_size: 1 << 26 }
    }
}

/// The parameters of an [`LZMA2Decompressor`](super::LZMA2Decompressor):
/// raw LZMA2 streams do not record their dictionary size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZMA2DecompressorConfig {
    /// The dictionary size the stream was made with (at least 4 KiB).
    pub dictionary_size: usize,
}

impl Default for LZMA2DecompressorConfig {
    fn default() -> LZMA2DecompressorConfig {
        LZMA2DecompressorConfig { dictionary_size: 1 << 23 }
    }
}
