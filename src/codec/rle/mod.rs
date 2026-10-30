//! Run-length encoding: PackBits ([`PackBitsFormat`]).

mod compressor;
mod decompressor;
mod format;

pub use compressor::PackBitsCompressor;
pub use decompressor::{PackBitsDecompressor, PackBitsState};
pub use format::PackBitsFormat;
