//! xxHash: fast non-cryptographic hash functions (the xxHash specification
//! 0.2.0). They detect accidental changes, not deliberate ones.

#[cfg(umilib_feature = "hash-xxhash-xxh3")]
pub mod xxh3;
#[cfg(umilib_feature = "hash-xxhash-xxh32")]
pub mod xxh32;
#[cfg(umilib_feature = "hash-xxhash-xxh64")]
pub mod xxh64;
