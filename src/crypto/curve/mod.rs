//! Elliptic curves of the specifications, as parameters of the generic
//! arithmetic of [`crate::math::ec`]: each module defines the fields of the
//! coordinates and of the scalars of its curves and a type implementing
//! [`WeierstrassCurve`](crate::math::ec::WeierstrassCurve),
//! [`MontgomeryCurve`](crate::math::ec::MontgomeryCurve) or
//! [`EdwardsCurve`](crate::math::ec::EdwardsCurve), which the schemes (ECDH,
//! ECDSA, EdDSA and others) take as a parameter.

#[cfg(umilib_feature = "crypto-curve-brainpool")]
pub mod brainpool;
#[cfg(umilib_feature = "crypto-curve-curve25519")]
pub mod curve25519;
#[cfg(umilib_feature = "crypto-curve-curve448")]
pub mod curve448;
#[cfg(umilib_feature = "crypto-curve-gost")]
pub mod gost;
#[cfg(umilib_feature = "crypto-curve-p256")]
pub mod p256;
#[cfg(umilib_feature = "crypto-curve-p384")]
pub mod p384;
#[cfg(umilib_feature = "crypto-curve-p521")]
pub mod p521;
#[cfg(umilib_feature = "crypto-curve-secp256k1")]
pub mod secp256k1;
#[cfg(umilib_feature = "crypto-curve-sm2")]
pub mod sm2;
