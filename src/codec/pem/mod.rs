//! PEM: the textual encoding of PKIX, PKCS and CMS structures, RFC 7468.
//!
//! [`PEMDocument::decode_all`] finds every document in a text, ignoring the
//! explanatory text around them (RFC 7468 section 5.2), and parses each with
//! the grammar chosen by [`PEMStrictness`]. [`PEMDocument::encode`] always
//! writes the strict format, as new implementations should. Decoded data is
//! zeroized when a document is dropped, because it is often a private key.

mod config;
mod document;
mod error;
mod label;

pub use config::{PEMConfig, PEMLineEnding, PEMStrictness};
pub use document::PEMDocument;
pub use error::PEMError;
pub use label::PEMLabel;
