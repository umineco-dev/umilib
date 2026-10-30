//! The C ABI of [`crate::crypto::curve`].
//!
//! The curves are parameters of the schemes, named by the C type names of
//! their types, such as `umilib_crypto_curve_p256_P256`: the registries
//! [`ffi_weierstrass_curves!`](crate::ffi_weierstrass_curves) and
//! [`ffi_gost_curves!`](crate::ffi_gost_curves) list them; the Montgomery
//! and Edwards curves are named by the schemes that use them.

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

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "curve",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "crypto-curve-brainpool")]
        brainpool::MODULE,
        #[cfg(umilib_feature = "crypto-curve-curve25519")]
        curve25519::MODULE,
        #[cfg(umilib_feature = "crypto-curve-curve448")]
        curve448::MODULE,
        #[cfg(umilib_feature = "crypto-curve-gost")]
        gost::MODULE,
        #[cfg(umilib_feature = "crypto-curve-p256")]
        p256::MODULE,
        #[cfg(umilib_feature = "crypto-curve-p384")]
        p384::MODULE,
        #[cfg(umilib_feature = "crypto-curve-p521")]
        p521::MODULE,
        #[cfg(umilib_feature = "crypto-curve-secp256k1")]
        secp256k1::MODULE,
        #[cfg(umilib_feature = "crypto-curve-sm2")]
        sm2::MODULE,
    ],
};
