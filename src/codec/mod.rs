//! Codecs: conversions between representations of data, and compression.
//!
//! The compressed formats share the streaming interfaces [`Compressor`] and
//! [`Decompressor`], which work on caller-provided buffers without I/O
//! ([`Flush`], [`Progress`], [`CompressionError`]); [`PendingOutput`] holds
//! the bytes they made that did not fit the caller's output.

mod compression_error;
mod compressor;
mod decompressor;
mod pending_output;
mod progress;

pub use compression_error::CompressionError;
pub use compressor::{Compressor, Flush};
pub use decompressor::Decompressor;
pub use pending_output::PendingOutput;
pub use progress::Progress;

#[cfg(umilib_feature = "codec-asn1")]
pub mod asn1;
#[cfg(umilib_feature = "codec-base")]
pub mod base;
#[cfg(umilib_feature = "codec-brotli")]
pub mod brotli;
#[cfg(umilib_feature = "codec-deflate")]
pub mod deflate;
#[cfg(umilib_feature = "codec-filter")]
pub mod filter;
#[cfg(umilib_feature = "codec-gzip")]
pub mod gzip;
#[cfg(umilib_feature = "codec-hpack")]
pub mod hpack;
#[cfg(umilib_feature = "codec-huffman")]
pub mod huffman;
#[cfg(umilib_feature = "codec-json")]
pub mod json;
#[cfg(umilib_feature = "codec-lz4")]
pub mod lz4;
#[cfg(umilib_feature = "codec-lz77")]
pub mod lz77;
#[cfg(umilib_feature = "codec-lz78")]
pub mod lz78;
#[cfg(umilib_feature = "codec-lzma")]
pub mod lzma;
#[cfg(umilib_feature = "codec-lzss")]
pub mod lzss;
#[cfg(umilib_feature = "codec-mail")]
pub mod mail;
#[cfg(umilib_feature = "codec-pem")]
pub mod pem;
#[cfg(umilib_feature = "codec-qpack")]
pub mod qpack;
#[cfg(umilib_feature = "codec-rle")]
pub mod rle;
#[cfg(umilib_feature = "codec-stringprep")]
pub mod stringprep;
#[cfg(umilib_feature = "codec-uri")]
pub mod uri;
#[cfg(umilib_feature = "codec-xz")]
pub mod xz;
#[cfg(umilib_feature = "codec-zlib")]
pub mod zlib;
#[cfg(umilib_feature = "codec-zstandard")]
pub mod zstandard;
