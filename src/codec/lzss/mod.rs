//! LZSS in the format of Haruhiko Okumura's public-domain `lzss.c`
//! ([`LZSSFormat`]), whose parameters are an [`LZSSConfig`].

mod compressor;
mod config;
mod decompressor;
mod format;

pub use compressor::LZSSCompressor;
pub use config::LZSSConfig;
pub use decompressor::{LZSSDecompressor, LZSSState};
pub use format::LZSSFormat;
