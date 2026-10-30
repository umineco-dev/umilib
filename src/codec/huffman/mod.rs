//! Huffman coding: canonical prefix codes ([`canonical`]) and adaptive
//! Huffman coding ([`adaptive`]).

mod error;

pub use error::HuffmanError;

#[cfg(umilib_feature = "codec-huffman-adaptive")]
pub mod adaptive;
#[cfg(umilib_feature = "codec-huffman-canonical")]
pub mod canonical;
