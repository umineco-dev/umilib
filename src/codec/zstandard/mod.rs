//! Zstandard (RFC 8878): frames of blocks of Huffman-coded literals and
//! FSE-coded sequences ([`ZstandardCompressor`], [`ZstandardDecompressor`]),
//! dictionaries, and the entropy coders they are built from ([`FSEDistribution`],
//! [`FSEDecodingTable`], [`FSEEncodingTable`], [`ZstandardHuffman`]).

mod bitstream;
mod block;
mod compressor;
mod config;
mod decompressor;
mod dictionary;
mod format;
mod fse;
mod huffman;
mod literals;
mod sequences;

pub use bitstream::{ZstandardBitReader, ZstandardBitWriter};
pub use block::{ZstandardBlockDecoder, ZstandardBlockEncoder, ZstandardLevel};
pub use compressor::ZstandardCompressor;
pub use config::{ZstandardConfig, ZstandardDecompressorConfig};
pub use decompressor::{ZstandardDecompressor, ZstandardState};
pub use dictionary::ZstandardDictionary;
pub use format::ZstandardFormat;
pub use fse::{FSEDecodingEntry, FSEDecodingTable, FSEDistribution, FSEEncodingTable};
pub use huffman::ZstandardHuffman;
pub use literals::ZstandardLiterals;
pub use sequences::{ZstandardOffsets, ZstandardSequence, ZstandardSequenceTables, ZstandardSequences};
