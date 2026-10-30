//! Keys and algorithm identifiers of the X.509 public-key infrastructure:
//! - the identifiers of signature and key algorithms (RFC 3279, RFC 4055,
//!   RFC 5480, RFC 5758, RFC 8410, RFC 9881, RFC 9909, RFC 9935);
//! - public keys (`SubjectPublicKeyInfo`) and the verification of signatures;
//! - private keys (PKCS #8 `OneAsymmetricKey`, RFC 5958, with the private
//!   key formats of each algorithm) and signing;
//! - private keys encrypted with PBES2 (RFC 8018, RFC 5958 §3).

/// Evaluates `$body` with `$H` the hash type of `$hash`, a
/// [`HashAlgorithm`] that is not an extendable-output function; evaluates
/// `$xof` for SHAKE128 and SHAKE256.
macro_rules! with_digest {
    ($hash:expr, $H:ident => $body:expr, xof => $xof:expr) => {
        match $hash {
            $crate::auth::cert::key::HashAlgorithm::SHA1 => {
                type $H = $crate::hash::sha::v1::SHA1;
                $body
            }
            $crate::auth::cert::key::HashAlgorithm::SHA224 => {
                type $H = $crate::hash::sha::v2::SHA224;
                $body
            }
            $crate::auth::cert::key::HashAlgorithm::SHA256 => {
                type $H = $crate::hash::sha::v2::SHA256;
                $body
            }
            $crate::auth::cert::key::HashAlgorithm::SHA384 => {
                type $H = $crate::hash::sha::v2::SHA384;
                $body
            }
            $crate::auth::cert::key::HashAlgorithm::SHA512 => {
                type $H = $crate::hash::sha::v2::SHA512;
                $body
            }
            $crate::auth::cert::key::HashAlgorithm::SHA512_224 => {
                type $H = $crate::hash::sha::v2::SHA512_224;
                $body
            }
            $crate::auth::cert::key::HashAlgorithm::SHA512_256 => {
                type $H = $crate::hash::sha::v2::SHA512_256;
                $body
            }
            $crate::auth::cert::key::HashAlgorithm::SHA3_224 => {
                type $H = $crate::hash::sha::v3::SHA3_224;
                $body
            }
            $crate::auth::cert::key::HashAlgorithm::SHA3_256 => {
                type $H = $crate::hash::sha::v3::SHA3_256;
                $body
            }
            $crate::auth::cert::key::HashAlgorithm::SHA3_384 => {
                type $H = $crate::hash::sha::v3::SHA3_384;
                $body
            }
            $crate::auth::cert::key::HashAlgorithm::SHA3_512 => {
                type $H = $crate::hash::sha::v3::SHA3_512;
                $body
            }
            $crate::auth::cert::key::HashAlgorithm::SHAKE128 | $crate::auth::cert::key::HashAlgorithm::SHAKE256 => $xof,
        }
    };
}

/// Evaluates `$body` with `$C` the curve type of `$curve`, a
/// [`NamedCurve`]; a curve whose feature is disabled gives
/// `Err(KeyError::Unsupported)`.
macro_rules! with_curve {
    ($curve:expr, $C:ident => $body:expr) => {
        match $curve {
            $crate::auth::cert::key::NamedCurve::P256 => {
                type $C = $crate::crypto::curve::p256::P256;
                $body
            }
            $crate::auth::cert::key::NamedCurve::P384 => {
                type $C = $crate::crypto::curve::p384::P384;
                $body
            }
            $crate::auth::cert::key::NamedCurve::P521 => {
                type $C = $crate::crypto::curve::p521::P521;
                $body
            }
            #[cfg(umilib_feature = "crypto-curve-secp256k1")]
            $crate::auth::cert::key::NamedCurve::Secp256k1 => {
                type $C = $crate::crypto::curve::secp256k1::Secp256k1;
                $body
            }
            #[cfg(umilib_feature = "crypto-curve-brainpool-p256r1")]
            $crate::auth::cert::key::NamedCurve::BrainpoolP256r1 => {
                type $C = $crate::crypto::curve::brainpool::p256r1::BrainpoolP256r1;
                $body
            }
            #[cfg(umilib_feature = "crypto-curve-brainpool-p384r1")]
            $crate::auth::cert::key::NamedCurve::BrainpoolP384r1 => {
                type $C = $crate::crypto::curve::brainpool::p384r1::BrainpoolP384r1;
                $body
            }
            #[cfg(umilib_feature = "crypto-curve-brainpool-p512r1")]
            $crate::auth::cert::key::NamedCurve::BrainpoolP512r1 => {
                type $C = $crate::crypto::curve::brainpool::p512r1::BrainpoolP512r1;
                $body
            }
            #[allow(unreachable_patterns)]
            _ => Err($crate::auth::cert::key::KeyError::Unsupported),
        }
    };
}

/// Evaluates `$body` with `$P` the parameter type of `$set`, an [`MLDSAParameterSet`].
macro_rules! with_mldsa {
    ($set:expr, $P:ident => $body:expr) => {
        match $set {
            $crate::auth::cert::key::MLDSAParameterSet::MLDSA44 => {
                type $P = $crate::crypto::mldsa::MLDSA44;
                $body
            }
            $crate::auth::cert::key::MLDSAParameterSet::MLDSA65 => {
                type $P = $crate::crypto::mldsa::MLDSA65;
                $body
            }
            $crate::auth::cert::key::MLDSAParameterSet::MLDSA87 => {
                type $P = $crate::crypto::mldsa::MLDSA87;
                $body
            }
        }
    };
}

/// Evaluates `$body` with `$P` the parameter type of `$set`, an [`MLKEMParameterSet`].
macro_rules! with_mlkem {
    ($set:expr, $P:ident => $body:expr) => {
        match $set {
            $crate::auth::cert::key::MLKEMParameterSet::MLKEM512 => {
                type $P = $crate::crypto::mlkem::MLKEM512;
                $body
            }
            $crate::auth::cert::key::MLKEMParameterSet::MLKEM768 => {
                type $P = $crate::crypto::mlkem::MLKEM768;
                $body
            }
            $crate::auth::cert::key::MLKEMParameterSet::MLKEM1024 => {
                type $P = $crate::crypto::mlkem::MLKEM1024;
                $body
            }
        }
    };
}

/// Evaluates `$body` with `$P` the parameter type of `$set`, an [`SLHDSAParameterSet`].
macro_rules! with_slhdsa {
    ($set:expr, $P:ident => $body:expr) => {
        with_slhdsa!(@sets $set, $P => $body;
            SHA2_128s SLHDSA_SHA2_128s, SHA2_128f SLHDSA_SHA2_128f, SHA2_192s SLHDSA_SHA2_192s,
            SHA2_192f SLHDSA_SHA2_192f, SHA2_256s SLHDSA_SHA2_256s, SHA2_256f SLHDSA_SHA2_256f,
            SHAKE_128s SLHDSA_SHAKE_128s, SHAKE_128f SLHDSA_SHAKE_128f, SHAKE_192s SLHDSA_SHAKE_192s,
            SHAKE_192f SLHDSA_SHAKE_192f, SHAKE_256s SLHDSA_SHAKE_256s, SHAKE_256f SLHDSA_SHAKE_256f)
    };
    (@sets $set:expr, $P:ident => $body:expr; $($variant:ident $type:ident),*) => {
        match $set {
            $(
                $crate::auth::cert::key::SLHDSAParameterSet::$variant => {
                    type $P = $crate::crypto::slhdsa::$type;
                    $body
                }
            )*
        }
    };
}

mod error;
mod identifiers;
mod pbes2;
mod pkcs8;
mod private_key;
mod public_key;

pub use error::KeyError;
pub use identifiers::{
    AlgorithmIdentifier, HashAlgorithm, KeyAlgorithm, MLDSAParameterSet, MLKEMParameterSet, NamedCurve, PSSParameters,
    SLHDSAParameterSet, SignatureAlgorithm,
};
pub use pbes2::{EncryptedPrivateKeyInfo, PBES2Cipher, PBES2Config, PBES2Parameters};
pub use pkcs8::{ECPrivateKey, PrivateKeyInfo, SeedChoice};
pub use private_key::PrivateKey;
pub use public_key::{KeyLimits, PublicKey, SubjectPublicKeyInfo};
