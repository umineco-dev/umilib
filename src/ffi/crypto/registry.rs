//! The registries of the curves that the public-key schemes of the C ABI
//! take as parameters, by the C type names of their types (such as
//! `umilib_crypto_curve_p256_P256`). A registry is a macro that calls
//! `$callback!` with one line per curve, each behind the `umilib_feature`
//! cfg of its feature in the callback, as
//! [`ffi_digest_algorithms!`](crate::ffi_digest_algorithms) does for hash
//! functions.

/// The registry of the short Weierstrass curves of [`crate::crypto::curve`]
/// for ECDH and ECDSA: `$callback!` receives one line per curve, `feature
/// Variant => type, "C type name";`.
#[macro_export]
macro_rules! ffi_weierstrass_curves {
    ($callback:ident) => {
        $callback! {
            "crypto-curve-p256" P256 => $crate::crypto::curve::p256::P256, "umilib_crypto_curve_p256_P256";
            "crypto-curve-p384" P384 => $crate::crypto::curve::p384::P384, "umilib_crypto_curve_p384_P384";
            "crypto-curve-p521" P521 => $crate::crypto::curve::p521::P521, "umilib_crypto_curve_p521_P521";
            "crypto-curve-secp256k1" Secp256k1 => $crate::crypto::curve::secp256k1::Secp256k1, "umilib_crypto_curve_secp256k1_Secp256k1";
            "crypto-curve-brainpool-p256r1" BrainpoolP256r1 => $crate::crypto::curve::brainpool::p256r1::BrainpoolP256r1, "umilib_crypto_curve_brainpool_p256r1_BrainpoolP256r1";
            "crypto-curve-brainpool-p384r1" BrainpoolP384r1 => $crate::crypto::curve::brainpool::p384r1::BrainpoolP384r1, "umilib_crypto_curve_brainpool_p384r1_BrainpoolP384r1";
            "crypto-curve-brainpool-p512r1" BrainpoolP512r1 => $crate::crypto::curve::brainpool::p512r1::BrainpoolP512r1, "umilib_crypto_curve_brainpool_p512r1_BrainpoolP512r1";
            "crypto-curve-sm2" SM2 => $crate::crypto::curve::sm2::SM2, "umilib_crypto_curve_sm2_SM2";
        }
    };
}

/// The registry of the curves of GOST R 34.10-2012, as
/// [`ffi_weierstrass_curves!`](crate::ffi_weierstrass_curves), each with the
/// Streebog of its size (RFC 9215 section 2): `feature Variant => type,
/// "C type name", hash type, "hash C type name";`.
#[macro_export]
macro_rules! ffi_gost_curves {
    ($callback:ident) => {
        $callback! {
            "crypto-curve-gost" GOST256A => $crate::crypto::curve::gost::GOST256A, "umilib_crypto_curve_gost_GOST256A", $crate::hash::streebog::Streebog256, "umilib_hash_streebog_Streebog256";
            "crypto-curve-gost" GOST256B => $crate::crypto::curve::gost::GOST256B, "umilib_crypto_curve_gost_GOST256B", $crate::hash::streebog::Streebog256, "umilib_hash_streebog_Streebog256";
            "crypto-curve-gost" GOST256C => $crate::crypto::curve::gost::GOST256C, "umilib_crypto_curve_gost_GOST256C", $crate::hash::streebog::Streebog256, "umilib_hash_streebog_Streebog256";
            "crypto-curve-gost" GOST256D => $crate::crypto::curve::gost::GOST256D, "umilib_crypto_curve_gost_GOST256D", $crate::hash::streebog::Streebog256, "umilib_hash_streebog_Streebog256";
            "crypto-curve-gost" GOST512A => $crate::crypto::curve::gost::GOST512A, "umilib_crypto_curve_gost_GOST512A", $crate::hash::streebog::Streebog512, "umilib_hash_streebog_Streebog512";
            "crypto-curve-gost" GOST512B => $crate::crypto::curve::gost::GOST512B, "umilib_crypto_curve_gost_GOST512B", $crate::hash::streebog::Streebog512, "umilib_hash_streebog_Streebog512";
            "crypto-curve-gost" GOST512C => $crate::crypto::curve::gost::GOST512C, "umilib_crypto_curve_gost_GOST512C", $crate::hash::streebog::Streebog512, "umilib_hash_streebog_Streebog512";
        }
    };
}
