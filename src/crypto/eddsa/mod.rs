//! The Edwards-curve digital signature algorithm of RFC 8032.
//!
//! [`EdDSA`] signs with a twisted Edwards curve that implements
//! [`EdDSACurve`], which adds the hash function and the parameters of RFC
//! 8032: [`Ed25519`] (section 5.1, with SHA-512) and [`Ed448`] (section 5.2,
//! with SHAKE256). They implement
//! [`SignatureScheme`](crate::crypto::SignatureScheme) with the pure
//! variants, Ed25519 and Ed448; [`EdDSA::sign_with_context`] gives
//! Ed25519ctx and Ed448 with a context, and [`EdDSA::sign_prehashed`]
//! Ed25519ph and Ed448ph.
//!
//! Signatures are deterministic. Verification checks the encodings strictly
//! (a point must be canonical, S below the order L) and the cofactored
//! equation \[2^c\]\[S\]B = \[2^c\]R + \[2^c\]\[k\]A, the first of section 5.1.7 step 3.

mod curve;
// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod eddsa;

pub use curve::EdDSACurve;
pub use eddsa::{EdDSA, EdDSASigningKey, EdDSAVerifyingKey};

/// Ed25519 of RFC 8032 section 5.1.
pub type Ed25519 = EdDSA<crate::crypto::curve::curve25519::Edwards25519>;

/// Ed448 of RFC 8032 section 5.2.
pub type Ed448 = EdDSA<crate::crypto::curve::curve448::Edwards448>;
