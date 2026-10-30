//! Binary-to-text encodings: Base16, Base32 and Base64 (RFC 4648), Base58 and Base85.
//!
//! Every encoding implements [`Encoding`]. Base16, Base32 and Base64 share
//! [`BitEncoding`], which maps groups of bits to characters of an
//! [`Alphabet`] without branches or table lookups that depend on the data, so
//! they can encode and decode secrets (keys in PEM files, for example).

mod alphabet;
mod bit_encoding;
mod encoding;
mod error;
mod padding;

pub use alphabet::{Alphabet, AlphabetRange};
pub use bit_encoding::BitEncoding;
pub use encoding::Encoding;
pub use error::BaseError;
pub use padding::Padding;

#[cfg(umilib_feature = "codec-base-base16")]
pub mod base16;
#[cfg(umilib_feature = "codec-base-base32")]
pub mod base32;
#[cfg(umilib_feature = "codec-base-base58")]
pub mod base58;
#[cfg(umilib_feature = "codec-base-base64")]
pub mod base64;
#[cfg(umilib_feature = "codec-base-base85")]
pub mod base85;
