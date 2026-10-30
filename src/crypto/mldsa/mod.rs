//! ML-DSA, the module-lattice-based digital signature algorithm of FIPS
//! 204, with the parameter sets [`MLDSA44`], [`MLDSA65`] and [`MLDSA87`]:
//! `MLDSA<MLDSA65>` implements [`SignatureScheme`](crate::crypto::SignatureScheme)
//! (deterministic, empty context) and has the signing and verification
//! functions of sections 5 and 6 with contexts, hedged randomness,
//! pre-hashing (HashML-DSA) and the message representative μ.
//!
//! A private key ([`MLDSASigningKey`]) is read from its encoding only if its
//! s1 and s2 are in range and its t0 and tr are those its other parts
//! define; it can also be kept as the seed ξ of 32 bytes it is generated
//! from (`signing_key_from_seed`, `write_seed`). The arithmetic is that of
//! [`MLDSARing`](crate::math::lattice::MLDSARing); the secret parts are
//! handled in constant time, except the rejection of the signing loop and
//! of RejBoundedPoly, whose number of iterations FIPS 204 lets reveal.

mod functions;
mod keys;
// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod mldsa;
mod parameters;

pub use functions::MLDSAFunctions;
pub use keys::{MLDSASigningKey, MLDSAVerifyingKey};
pub use mldsa::MLDSA;
pub use parameters::{MLDSA44, MLDSA65, MLDSA87, MLDSAParameters};
