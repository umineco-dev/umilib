//! The elliptic curve digital signature algorithm (FIPS 186-5 section 6,
//! SEC 1 section 4.1) with deterministic nonces (RFC 6979).
//!
//! [`ECDSA`] signs with a short Weierstrass curve `C` and a hash function
//! `H`, such as `ECDSA<P256, SHA256>`; it implements
//! [`SignatureScheme`](crate::crypto::SignatureScheme) with signatures of r
//! and s big-endian, each of the length of the order (the form of IEEE 1363
//! and of JOSE). [`ECDSASignature`] also reads and writes the DER encoding
//! of SEC 1 section C.5 (`Ecdsa-Sig-Value`) when `codec-asn1-der` is enabled.
//!
//! The nonce k is the one of RFC 6979 section 3.2 (HMAC_DRBG over `H` seeded
//! with the key and the digest), so that a signature never depends on a
//! source of random bytes; [`ECDSA::sign_digest_hedged`] adds random bytes
//! to the seed as RFC 6979 section 3.6 allows. Signing is constant time in
//! the key and the nonce; verification is not, as its inputs are public.

// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod ecdsa;
mod signature;

pub use ecdsa::{ECDSA, ECDSASigningKey, ECDSAVerifyingKey};
pub use signature::ECDSASignature;
