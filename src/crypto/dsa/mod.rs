//! The digital signature algorithm of FIPS 186-4 section 4 with
//! deterministic nonces (RFC 6979).
//!
//! FIPS 186-5 keeps DSA for the verification of existing signatures only;
//! signing is provided for protocols that still require it. [`DSA`] signs
//! with a hash function `H` under keys of [`DSAParameters`] (p, q, g) of the
//! sizes (L, N) of FIPS 186-4 section 4.2: (1024, 160), (2048, 224),
//! (2048, 256) and (3072, 256). [`DSASignature`] has the fixed encoding of r
//! and s, each of the bytes of q, and the DER encoding of RFC 3279 section
//! 2.2.2 (`Dss-Sig-Value`) with `codec-asn1-der`.

// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod dsa;
mod parameters;
mod signature;

pub use dsa::{DSA, DSASigningKey, DSAVerifyingKey};
pub use parameters::DSAParameters;
pub use signature::DSASignature;
