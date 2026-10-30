//! Elliptic curve Diffie–Hellman.
//!
//! [`ECDH`] is the key agreement of SEC 1 section 3.3.1 (and of SP 800-56A
//! revision 3 section 5.7.1.2) on a short Weierstrass curve, such as
//! `ECDH<P256>`: the shared secret is the x-coordinate of the product of the
//! private key and the public key, big-endian. Public keys are SEC 1 points,
//! validated as SEC 1 section 3.2.2.1 requires.
//!
//! [`XDH`] is the key agreement of RFC 7748 on a Montgomery curve: [`X25519`]
//! and [`X448`]. Every encoding of a public key is accepted, and a shared
//! secret of zero, the result of a public key of small order, is refused
//! (RFC 7748 section 6, as TLS 1.3 and HPKE require).
//!
//! Both implement [`KeyAgreement`](crate::crypto::KeyAgreement) and compute
//! in constant time in their private keys.

// Each type has the file of its name, here the name of its parent too.
#[allow(clippy::module_inception)]
mod ecdh;
mod xdh;

pub use ecdh::{ECDH, ECDHPrivateKey, ECDHPublicKey};
#[cfg(umilib_feature = "crypto-curve-curve448")]
pub use xdh::X448;
#[cfg(umilib_feature = "crypto-curve-curve25519")]
pub use xdh::X25519;
pub use xdh::{XDH, XDHPrivateKey, XDHPublicKey};
