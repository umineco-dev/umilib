//! Hash functions: cryptographic digests, extendable-output functions,
//! checksums and fast non-cryptographic hashes.
//!
//! Every function with a fixed output implements [`Digest`] (and the
//! cryptographic ones [`CryptographicDigest`]), and every extendable-output
//! function of a byte string [`ExtendableOutput`]; TupleHash, whose input is
//! a sequence of strings, has the same methods under its own names. States of cryptographic
//! functions are zeroed when dropped, because they hold the hashed data, which
//! may be secret. [`BlockBuffer`] holds the partial block of block-based
//! functions and applies the Merkle–Damgård padding.

mod block_buffer;
mod cryptographic_digest;
mod digest;
mod error;
mod extendable_output;

pub use block_buffer::BlockBuffer;
pub use cryptographic_digest::CryptographicDigest;
pub use digest::Digest;
pub use error::HashError;
pub use extendable_output::{ExtendableOutput, XOFReader};

#[cfg(umilib_feature = "hash-adler32")]
pub mod adler32;
#[cfg(umilib_feature = "hash-ascon")]
pub mod ascon;
#[cfg(umilib_feature = "hash-blake")]
pub mod blake;
#[cfg(umilib_feature = "hash-crc")]
pub mod crc;
#[cfg(umilib_feature = "hash-md")]
pub mod md;
#[cfg(umilib_feature = "hash-ripemd")]
pub mod ripemd;
#[cfg(umilib_feature = "hash-sha")]
pub mod sha;
#[cfg(umilib_feature = "hash-siphash")]
pub mod siphash;
#[cfg(umilib_feature = "hash-sm3")]
pub mod sm3;
#[cfg(umilib_feature = "hash-streebog")]
pub mod streebog;
#[cfg(umilib_feature = "hash-xxhash")]
pub mod xxhash;
