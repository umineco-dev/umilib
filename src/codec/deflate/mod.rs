//! Deflate (RFC 1951): raw streams of blocks of LZ77 symbols coded with
//! fixed or dynamic Huffman codes, or stored. zlib (RFC 1950) and gzip
//! (RFC 1952) wrap these streams.

mod block;
mod compressor;
mod config;
mod decompressor;
mod format;

pub use block::{DeflateBlock, DeflateBlockKind, DeflateSymbol};
pub use compressor::DeflateCompressor;
pub use config::{DeflateConfig, DeflateDecompressorConfig, DeflateLevel};
pub use decompressor::{DeflateDecompressor, DeflateState};
pub use format::DeflateFormat;
