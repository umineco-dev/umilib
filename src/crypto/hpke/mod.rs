//! Hybrid Public Key Encryption (HPKE, RFC 9180).
//!
//! [`HPKE`] combines a key encapsulation mechanism `K` ([`HPKEKEM`]), a key
//! derivation function `F` ([`HPKEKDF`]) and an AEAD `A` ([`HPKEAEAD`]) into
//! the modes base, PSK, auth and auth-PSK of section 5. The KEMs are the
//! DHKEMs of section 4.1 ([`DHKEM`]) over the key agreements of
//! [`crypto::ecdh`](crate::crypto::ecdh): P-256, P-384, P-521, X25519 and
//! X448; the KDFs are HKDF with SHA-256, SHA-384 and SHA-512; the AEADs are
//! AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 and the export-only AEAD
//! ([`HPKEExportOnly`]), each available with the features of its parts.
//!
//! A sender context ([`HPKESenderContext`]) only seals and a receiver
//! context ([`HPKEReceiverContext`]) only opens, each counting its own
//! sequence numbers, so that no nonce repeats under a key.

mod aead;
mod context;
// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod hpke;
mod kdf;
mod kem;

pub use aead::{HPKEAEAD, HPKEExportOnly};
pub use context::{HPKEContext, HPKEReceiverContext, HPKESenderContext};
pub use hpke::{HPKE, HPKEMode};
pub use kdf::{HPKEKDF, HPKELabels};
pub use kem::{DHKEM, DHKEMGroup, HPKEKEM};
