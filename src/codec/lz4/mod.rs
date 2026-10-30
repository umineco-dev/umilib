//! LZ4: the block format ([`LZ4Block`]) and the frame format
//! ([`LZ4Compressor`], [`LZ4Decompressor`]) of lz4_Block_format.md and
//! lz4_Frame_format.md.

mod block;
mod compressor;
mod config;
mod decompressor;
mod format;

pub use block::LZ4Block;
pub use compressor::LZ4Compressor;
pub use config::{LZ4Config, LZ4DecompressorConfig};
pub use decompressor::{LZ4Decompressor, LZ4State};
pub use format::{LZ4BlockSize, LZ4FrameFormat};
