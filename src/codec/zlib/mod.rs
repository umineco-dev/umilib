//! zlib (RFC 1950): Deflate streams with a header and an Adler-32 checksum.

mod compressor;
mod decompressor;
mod format;

pub use compressor::ZlibCompressor;
pub use decompressor::{ZlibDecompressor, ZlibState};
pub use format::ZlibFormat;
