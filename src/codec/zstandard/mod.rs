//! Zstandard (RFC 8878): frames of blocks of Huffman-coded literals and
//! FSE-coded sequences ([`ZstandardCompressor`], [`ZstandardDecompressor`]),
//! dictionaries, and the parts of blocks ([`ZstandardHuffman`],
//! [`ZstandardLiterals`], [`ZstandardSequences`]). The FSE coder is
//! [`crate::codec::fse`]; the backward bitstreams are
//! [`BackwardBitReader`](crate::bytes::BackwardBitReader) and
//! [`BackwardBitWriter`](crate::bytes::BackwardBitWriter).

mod block;
mod compressor;
mod config;
mod decompressor;
mod dictionary;
mod format;
mod huffman;
mod literals;
mod sequences;

pub use block::{ZstandardBlockDecoder, ZstandardBlockEncoder, ZstandardLevel};
pub use compressor::ZstandardCompressor;
pub use config::{ZstandardConfig, ZstandardDecompressorConfig};
pub use decompressor::{ZstandardDecompressor, ZstandardState};
pub use dictionary::ZstandardDictionary;
pub use format::ZstandardFormat;
pub use huffman::ZstandardHuffman;
pub use literals::ZstandardLiterals;
pub use sequences::{ZstandardOffsets, ZstandardSequence, ZstandardSequenceTables, ZstandardSequences};
