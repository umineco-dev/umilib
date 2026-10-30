//! The Distinguished Encoding Rules (X.690 sections 10 and 11).
//!
//! [`DERReader`] accepts only the single DER encoding of each value: definite
//! minimal lengths, primitive strings, `0xFF` for true, zero padding bits,
//! SET components sorted by tag and SET OF components sorted by encoding
//! ([`DERSetOrder`]), and the DER forms of times and reals. [`DERWriter`]
//! writes exactly that encoding.

mod element;
mod reader;
mod set_order;
mod writer;

pub use element::DERElement;
pub use reader::DERReader;
pub use set_order::DERSetOrder;
pub use writer::DERWriter;
