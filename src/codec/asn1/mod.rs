//! ASN.1 encodings, ITU-T X.690: BER and DER.
//!
//! This module holds what both encodings share: tags, object identifiers,
//! and the content formats of the universal types. [`der`] reads and writes
//! the Distinguished Encoding Rules strictly (every value has exactly one
//! encoding, as signatures require); [`ber`] reads the Basic Encoding Rules,
//! which allow many encodings of a value, and converts them to DER.

mod bit_string;
mod error;
mod integer;
mod object_identifier;
mod real;
mod string;
mod tag;
mod time;

pub use bit_string::BitString;
pub use error::ASN1Error;
pub use integer::ASN1Integer;
pub use object_identifier::ObjectIdentifier;
pub use real::ASN1Real;
pub use string::ASN1String;
pub use tag::{Tag, TagClass};
pub use time::ASN1Time;

#[cfg(umilib_feature = "codec-asn1-ber")]
pub mod ber;
#[cfg(umilib_feature = "codec-asn1-der")]
pub mod der;
