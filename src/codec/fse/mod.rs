//! Finite State Entropy (FSE), the tabled asymmetric numeral system (tANS)
//! of Jarek Duda as Yann Collet's FSE library implements it and Zstandard
//! (RFC 8878 section 4.1) uses it: normalized distributions and their table
//! descriptions ([`FSEDistribution`]), and the decoding and encoding tables
//! of a distribution ([`FSEDecodingTable`], [`FSEEncodingTable`]). The
//! tables drive a [`BackwardBitReader`](crate::bytes::BackwardBitReader)
//! and a [`BackwardBitWriter`](crate::bytes::BackwardBitWriter), the
//! bitstreams of the FSE library, or expose their steps for any other.

mod decoding_table;
mod distribution;
mod encoding_table;

pub use decoding_table::{FSEDecodingEntry, FSEDecodingTable};
pub use distribution::FSEDistribution;
pub use encoding_table::FSEEncodingTable;
