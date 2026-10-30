//! BLAKE2 (RFC 7693, with the parallel and extendable-output variants of
//! the BLAKE2 specification) and BLAKE3.

#[cfg(umilib_feature = "hash-blake-v2")]
pub mod v2;
#[cfg(umilib_feature = "hash-blake-v3")]
pub mod v3;
