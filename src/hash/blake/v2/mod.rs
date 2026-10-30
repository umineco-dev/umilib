//! BLAKE2 (RFC 7693 and "BLAKE2: simpler, smaller, fast as MD5", with the
//! BLAKE2X specification).
//!
//! [`BLAKE2b`] (64-bit words, up to 64 bytes of output) and [`BLAKE2s`]
//! (32-bit words, up to 32 bytes) take a key, a salt, a personalization and
//! the tree parameters ([`BLAKE2bParameters`], [`BLAKE2sParameters`]); the
//! fixed-length functions such as [`BLAKE2b512`] implement
//! [`Digest`](crate::hash::Digest). [`BLAKE2bp`] and [`BLAKE2sp`] hash 4 and 8
//! interleaved lanes and combine them, and [`BLAKE2Xb`] and [`BLAKE2Xs`]
//! produce outputs of any length up to 2^32 - 1 and 2^16 - 1 bytes.

mod engine;
mod fixed;
mod parallel;
mod parameters;
mod xof;

pub use engine::{BLAKE2b, BLAKE2s};
pub use fixed::{BLAKE2b160, BLAKE2b256, BLAKE2b384, BLAKE2b512, BLAKE2s128, BLAKE2s160, BLAKE2s224, BLAKE2s256};
pub use parallel::{BLAKE2bp, BLAKE2sp};
pub use parameters::{BLAKE2bParameters, BLAKE2sParameters};
pub use xof::{BLAKE2Xb, BLAKE2XbReader, BLAKE2Xs, BLAKE2XsReader};
