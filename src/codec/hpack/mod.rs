//! HPACK, the field compression of HTTP/2 (RFC 7541): prefixed integers
//! ([`HPACKInteger`]), string literals with the Huffman code of the RFC
//! ([`HPACKString`], [`HPACKHuffman`]), the static and dynamic tables
//! ([`HPACKStaticTable`], [`HPACKDynamicTable`]), and an encoder and a
//! decoder of field blocks ([`HPACKEncoder`], [`HPACKDecoder`]), every
//! limit of which is configurable. QPACK (RFC 9204) uses the integers,
//! strings and Huffman code of this module.

mod config;
mod decoder;
mod encoder;
mod error;
mod field;
mod huffman;
mod integer;
mod string;
mod table;

pub use config::{HPACKDecoderConfig, HPACKEncoderConfig};
pub use decoder::HPACKDecoder;
pub use encoder::HPACKEncoder;
pub use error::HPACKError;
pub use field::HPACKField;
pub use huffman::HPACKHuffman;
pub use integer::HPACKInteger;
pub use string::HPACKString;
pub use table::{HPACKDynamicTable, HPACKEntry, HPACKStaticTable};
