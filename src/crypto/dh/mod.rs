//! Finite field Diffie–Hellman over the safe-prime groups of RFC 7919
//! (ffdhe2048 to ffdhe8192, those of TLS) and RFC 3526 (the MODP groups of
//! IKE), as SP 800-56A revision 3 sections 5.6 and 5.7.1.1 define it.
//!
//! [`DH`] implements [`KeyAgreement`](crate::crypto::KeyAgreement) for a
//! [`DHGroup`], such as `DH<FFDHE2048>`. Private keys are generated with
//! twice the security strength of the group in bits (section 5.6.1.1.4);
//! public keys are fully validated (2 ≤ y ≤ p - 2 and y^q = 1, section
//! 5.6.2.3.1); the shared secret Z = y^x mod p, which must not be 1, keeps
//! the bytes of p (RFC 7919 section 3, as TLS requires).

// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod dh;
mod group;
mod groups;

pub use dh::{DH, DHPrivateKey, DHPublicKey};
pub use group::DHGroup;
pub use groups::{
    FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192, MODP1536, MODP2048, MODP3072, MODP4096, MODP6144, MODP8192,
};
