use alloc::vec::Vec;

use super::{XZCheck, XZFilter};
use crate::codec::lzma::LZMAConfig;

/// The parameters of an [`XZCompressor`](super::XZCompressor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XZConfig {
    /// The LZMA2 compression (the level, properties and dictionary;
    /// `uncompressed_size` is not used).
    pub lzma: LZMAConfig,
    /// The Check of the Blocks: CRC64 by default, as xz.
    pub check: XZCheck,
    /// The filters before LZMA2 (at most 3, Delta and BCJ), in the order
    /// they see the data.
    pub filters: Vec<XZFilter>,
    /// The uncompressed bytes of a Block (a new Block starts after them);
    /// `None` for one Block, as xz does without threads.
    pub block_size: Option<u64>,
}

impl Default for XZConfig {
    fn default() -> XZConfig {
        XZConfig { lzma: LZMAConfig::default(), check: XZCheck::CRC64, filters: Vec::new(), block_size: None }
    }
}

/// The limits of an [`XZDecompressor`](super::XZDecompressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XZDecompressorConfig {
    /// The largest LZMA2 dictionary a Block may ask for (larger ones fail
    /// with `LimitExceeded`): 64 MiB by default, the dictionary of xz -9;
    /// the window grows with the data up to it.
    pub maximum_dictionary_size: u64,
    /// Whether the input is a .xz file of any number of Streams and Stream
    /// Padding, which ends with the input; otherwise one Stream, after which
    /// the input is not consumed (as an embedded .xz stream is read).
    pub multiple_streams: bool,
}

impl Default for XZDecompressorConfig {
    fn default() -> XZDecompressorConfig {
        XZDecompressorConfig { maximum_dictionary_size: 1 << 26, multiple_streams: true }
    }
}
