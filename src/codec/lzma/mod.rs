//! LZMA (lzma-specification of Igor Pavlov) and LZMA2: the range coder, the
//! model and the symbol coders, the .lzma file format ([`LZMACompressor`],
//! [`LZMADecompressor`]) and raw LZMA2 streams ([`LZMA2Compressor`],
//! [`LZMA2Decompressor`]).

mod compressor;
mod config;
mod decoder;
mod decompressor;
mod encoder;
mod format;
mod lzma2_compressor;
mod lzma2_decompressor;
mod model;
mod properties;
mod range;

pub use compressor::LZMACompressor;
pub use config::{LZMA2DecompressorConfig, LZMAConfig, LZMADecompressorConfig};
pub use decoder::{LZMADecoder, LZMASymbol};
pub use decompressor::{LZMADecompressor, LZMAState};
pub use encoder::{LZMAChoice, LZMAEncoder, LZMALevel};
pub use format::LZMAFormat;
pub use lzma2_compressor::LZMA2Compressor;
pub use lzma2_decompressor::{LZMA2Decompressor, LZMA2State};
pub use model::LZMAModel;
pub use properties::LZMAProperties;
pub use range::{LZMARangeDecoder, LZMARangeEncoder};
