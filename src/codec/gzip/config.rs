use super::GzipHeader;
use crate::codec::deflate::{DeflateConfig, DeflateDecompressorConfig};

/// The parameters of a [`GzipCompressor`](super::GzipCompressor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GzipConfig {
    pub deflate: DeflateConfig,
    /// The header of the member; its `extra_flags` are set from the level
    /// (2 for level 9, 4 for level 1) when 0.
    pub header: GzipHeader,
}

impl Default for GzipConfig {
    fn default() -> GzipConfig {
        GzipConfig { deflate: DeflateConfig::default(), header: GzipHeader::new() }
    }
}

/// The limits of a [`GzipDecompressor`](super::GzipDecompressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GzipDecompressorConfig {
    /// Whether the input is a gzip file of any number of members, each
    /// following the previous one (zero bytes after a member are taken as
    /// padding), which ends with the input; otherwise the stream is one
    /// member, after which the input is not consumed.
    pub multiple_members: bool,
    /// The longest name, comment or extra field kept (longer ones fail with `LimitExceeded`).
    pub maximum_field: usize,
    /// The window of the Deflate data. gzip, unlike zlib, does not announce
    /// the window a member uses, so a smaller one bounds memory at the cost
    /// of members whose matches reach farther, which fail with `LimitExceeded`;
    /// the whole 32 KiB of RFC 1951 by default.
    pub deflate: DeflateDecompressorConfig,
}

impl Default for GzipDecompressorConfig {
    fn default() -> GzipDecompressorConfig {
        GzipDecompressorConfig {
            multiple_members: true,
            maximum_field: 1 << 16,
            deflate: DeflateDecompressorConfig::default(),
        }
    }
}
