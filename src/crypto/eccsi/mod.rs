//! Elliptic Curve-Based Certificateless Signatures for Identity-Based
//! Encryption (ECCSI, RFC 6507).
//!
//! A key management service ([`ECCSIKMS`]) holds the secret KSAK and
//! publishes KPAK = \[KSAK\]G; for each identity it issues a secret signing
//! key SSK with a public validation token PVT ([`ECCSIUserKey`]). [`ECCSI`]
//! signs with them and verifies signatures (r || s || PVT) against an
//! identity and KPAK alone. The curve `C` must have a = -3 (section 4.1),
//! such as NIST P-256, and the hash `H` must give N bytes, the bytes of p
//! (SHA-256 for P-256, as RFC 6509 uses them).
//!
//! The ephemeral values v and j are random in the RFC; here j is derived as
//! RFC 6979 section 3.2 derives nonces (HMAC_DRBG over `H` seeded with the
//! SSK, HS and the message) and hedged with random bytes, so that a weak
//! source of random bytes cannot reveal the key.

// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod eccsi;
mod kms;
mod user_key;

pub use eccsi::ECCSI;
pub use kms::ECCSIKMS;
pub use user_key::ECCSIUserKey;
