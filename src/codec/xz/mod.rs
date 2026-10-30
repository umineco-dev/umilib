//! The .xz file format (The .xz File Format 1.2.1): Streams of Blocks
//! compressed with filter chains ending with LZMA2 ([`XZCompressor`],
//! [`XZDecompressor`]), their Checks (CRC32, CRC64, SHA-256), Block
//! Headers, Index and integers.

mod block;
mod check;
mod compressor;
mod config;
mod decompressor;
mod filter;
mod format;
mod index;

pub use block::XZBlockHeader;
pub use check::{XZCheck, XZChecksum};
pub use compressor::XZCompressor;
pub use config::{XZConfig, XZDecompressorConfig};
pub use decompressor::{XZDecompressor, XZState};
pub use filter::{XZFilter, XZFilterCoder};
pub use format::{XZFormat, XZIntegerReader};
pub use index::{XZIndex, XZIndexHash, XZIndexPhase, XZIndexReader};
