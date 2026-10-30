//! gzip (RFC 1952): files of members, each a header, a Deflate stream and
//! the CRC-32 and size of its data.

mod compressor;
mod config;
mod decompressor;
mod format;
mod header;

pub use compressor::GzipCompressor;
pub use config::{GzipConfig, GzipDecompressorConfig};
pub use decompressor::{GzipDecompressor, GzipState};
pub use format::GzipFormat;
pub use header::GzipHeader;
