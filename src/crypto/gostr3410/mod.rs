//! The digital signature of GOST R 34.10-2012 (RFC 7091) with the
//! encodings of RFC 9215.
//!
//! [`GOSTR3410`] signs with a short Weierstrass curve `C`, such as those of
//! [`crypto::curve::gost`](crate::crypto::curve::gost), and a hash function
//! `H` (Streebog-256 for curves of 256 bits, Streebog-512 for 512 bits, as
//! RFC 9215 section 2 requires). The digest is read as a little-endian
//! integer, the order of the vectors of GOST R 34.11-2012. A signature is
//! s then r, each big-endian (RFC 9215 section 2); a verifying key is x then
//! y, each little-endian (RFC 9215 section 3); a signing key is d
//! little-endian.
//!
//! The standard draws the nonce k at random; here it is derived as RFC 6979
//! section 3.2 derives it (HMAC_DRBG over `H` seeded with the key and the
//! digest), so that signatures are deterministic, and
//! [`GOSTR3410::sign_hedged`] adds random bytes to the seed.

// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod gostr3410;
mod keys;
mod signature;

pub use gostr3410::GOSTR3410;
pub use keys::{GOSTR3410SigningKey, GOSTR3410VerifyingKey};
pub use signature::GOSTR3410Signature;
