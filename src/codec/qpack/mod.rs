//! QPACK, the field compression of HTTP/3 (RFC 9204): the static table
//! ([`QPACKStaticTable`]), the dynamic table of absolute indices
//! ([`QPACKDynamicTable`]), and an encoder and a decoder
//! ([`QPACKEncoder`], [`QPACKDecoder`]) of field sections and of the
//! instructions on their streams, which the caller carries: QPACK itself
//! has no I/O. Integers, strings and the Huffman code are HPACK's (RFC
//! 9204 §4.1), from [`crate::codec::hpack`].

mod config;
mod decoder;
mod encoder;
mod error;
mod table;

pub use config::{QPACKDecoderConfig, QPACKEncoderConfig};
pub use decoder::{QPACKDecoded, QPACKDecoder};
pub use encoder::{QPACKEncoder, QPACKLine, QPACKSection};
pub use error::QPACKError;
pub use table::{QPACKDynamicTable, QPACKStaticTable};
