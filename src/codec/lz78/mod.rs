//! LZ78: the pairs of the original algorithm in a format of this library
//! ([`LZ78Format`]), with a dictionary of phrases ([`LZ78Dictionary`]).

mod compressor;
mod config;
mod decompressor;
mod dictionary;
mod format;

pub use compressor::LZ78Compressor;
pub use config::{LZ78Config, LZ78DecompressorConfig};
pub use decompressor::{LZ78Decompressor, LZ78State};
pub use dictionary::LZ78Dictionary;
pub use format::LZ78Format;
