//! SLH-DSA, the stateless hash-based digital signature algorithm of FIPS
//! 205, with its twelve parameter sets ([`SLHDSA_SHA2_128s`] to
//! [`SLHDSA_SHAKE_256f`]): `SLHDSA<SLHDSA_SHAKE_128f>` implements
//! [`SignatureScheme`](crate::crypto::SignatureScheme) (deterministic,
//! empty context) and has the signing and verification functions of
//! sections 9 and 10 with contexts, hedged randomness and pre-hashing
//! (HashSLH-DSA).
//!
//! The hash functions of a family ([`SLHDSAHash`]) are [`SLHDSASHAKE`],
//! [`SLHDSASHA2Category1`] and [`SLHDSASHA2Category3And5`]; the SHA2
//! families compress the block of PK.seed once per key. A private key is
//! read from its encoding only if PK.root is the root its seeds generate
//! (the check of section 3.1).

mod address;
mod hash;
mod keys;
mod parameters;
// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod slhdsa;

pub use address::SLHDSAAddress;
pub use hash::{SLHDSAHash, SLHDSAMGF1, SLHDSASHA2Category1, SLHDSASHA2Category3And5, SLHDSASHAKE};
pub use keys::{SLHDSASigningKey, SLHDSAVerifyingKey};
pub use parameters::{
    SLHDSA_SHA2_128f, SLHDSA_SHA2_128s, SLHDSA_SHA2_192f, SLHDSA_SHA2_192s, SLHDSA_SHA2_256f, SLHDSA_SHA2_256s,
    SLHDSA_SHAKE_128f, SLHDSA_SHAKE_128s, SLHDSA_SHAKE_192f, SLHDSA_SHAKE_192s, SLHDSA_SHAKE_256f, SLHDSA_SHAKE_256s,
    SLHDSALimits, SLHDSAParameters,
};
pub use slhdsa::SLHDSA;
