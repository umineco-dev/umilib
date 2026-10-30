//! The Basic Encoding Rules (X.690 section 8).
//!
//! BER allows several encodings of one value: lengths in more octets than
//! needed, the indefinite length form for constructed elements, strings split
//! into constructed segments, any non-zero octet for true, and more forms of
//! times. [`BERReader`] accepts all of them; [`BERReader::to_der`] converts an
//! encoding to the single DER encoding of the same value, for example before
//! checking a signature over it.

mod element;
mod reader;

pub use element::BERElement;
pub use reader::BERReader;
