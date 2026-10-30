//! Canonical prefix codes (RFC 1951 section 3.2.2): codes defined by their
//! lengths, built from frequencies with a length limit, and tables that
//! decode them from bit streams of either bit order; and a block format of
//! this library that compresses bytes with them ([`CanonicalHuffmanFormat`]).

mod code;
mod compressor;
mod config;
mod decompressor;
mod format;
mod table;

pub use code::HuffmanCode;
pub use compressor::CanonicalHuffmanCompressor;
pub use config::CanonicalHuffmanConfig;
pub use decompressor::{CanonicalHuffmanDecompressor, CanonicalHuffmanState};
pub use format::CanonicalHuffmanFormat;
pub use table::HuffmanTable;
