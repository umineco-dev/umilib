//! The Secure Hash Algorithms: SHA-1 and SHA-2 (FIPS 180-4) and SHA-3
//! (FIPS 202, with the cSHAKE, TupleHash and ParallelHash of SP 800-185).

#[cfg(umilib_feature = "hash-sha-v1")]
pub mod v1;
#[cfg(umilib_feature = "hash-sha-v2")]
pub mod v2;
#[cfg(umilib_feature = "hash-sha-v3")]
pub mod v3;
