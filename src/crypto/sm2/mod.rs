//! SM2, the public key algorithms of GB/T 32918-2016 (GM/T 0003-2012) on an
//! elliptic curve: digital signatures (part 2, [`SM2DSA`]), key exchange
//! (part 3, [`SM2KEP`]) and public key encryption (part 4, [`SM2PKE`]).
//!
//! Every scheme is generic over a short Weierstrass curve `C` and a hash
//! function `H`, by default the curve of SM2 (GB/T 32918.5,
//! [`crypto::curve::sm2::SM2`](crate::crypto::curve::sm2::SM2)) and SM3,
//! the parameters the standard recommends. A user's identity enters the
//! signature and the key exchange through Z = H(ENTL || ID || a || b || xG
//! || yG || xA || yA) ([`SM2PublicKey::identity_hash`]);
//! [`SM2DSA::DEFAULT_IDENTITY`] is the identity of GM/T 0009-2012 that
//! RFC 8998 uses when none is agreed.

mod dsa;
mod kdf;
mod kep;
mod keys;
mod pke;
mod signature;

pub use dsa::SM2DSA;
pub use kdf::SM2KDF;
pub use kep::{SM2KEP, SM2KeyConfirmation, SM2Role};
pub use keys::{SM2PrivateKey, SM2PublicKey};
pub use pke::{SM2CiphertextOrder, SM2PKE};
pub use signature::SM2Signature;
