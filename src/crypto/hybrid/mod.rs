//! Post-quantum/traditional hybrids: the key agreements of RFC 10024 for
//! TLS 1.3 ([`X25519MLKEM768`], [`SecP256r1MLKEM768`],
//! [`SecP384r1MLKEM1024`]) as KEMs, `HybridKEM<X25519MLKEM768>`, which
//! implements [`KeyEncapsulation`](crate::crypto::KeyEncapsulation).
//!
//! [`HybridKEM`] combines any KEM with any key agreement whose shares and
//! secrets are concatenated ([`HybridKEMParameters`]); its parts are those
//! of [`crypto::mlkem`](crate::crypto::mlkem) and
//! [`crypto::ecdh`](crate::crypto::ecdh), with their checks.

mod kem;
mod parameters;

pub use kem::{HybridDecapsulationKey, HybridEncapsulationKey, HybridKEM};
pub use parameters::{HybridKEMParameters, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768};
