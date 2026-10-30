//! The MD message digests of R. Rivest: MD4 (RFC 1320) and MD5 (RFC 1321).
//!
//! Both are broken for collision resistance (collisions take seconds); use
//! them only where a protocol requires them (NTLM, legacy checksums), never
//! for security.

#[cfg(umilib_feature = "hash-md-v4")]
pub mod v4;
#[cfg(umilib_feature = "hash-md-v5")]
pub mod v5;
