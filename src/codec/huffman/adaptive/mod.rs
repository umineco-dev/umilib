//! Adaptive Huffman coding by Vitter's algorithm Λ ([`AdaptiveHuffmanTree`]),
//! and a stream format of this library that compresses bytes with it
//! ([`AdaptiveHuffmanFormat`]).

mod compressor;
mod decompressor;
mod format;
mod node;
mod tree;

pub use compressor::AdaptiveHuffmanCompressor;
pub use decompressor::{AdaptiveHuffmanDecompressor, AdaptiveHuffmanState};
pub use format::AdaptiveHuffmanFormat;
pub use node::AdaptiveHuffmanNode;
pub use tree::AdaptiveHuffmanTree;
